/*!
 * express-session
 * Copyright(c) 2010 Sencha Inc.
 * Copyright(c) 2011 TJ Holowaychuk
 * Copyright(c) 2014-2015 Douglas Christopher Wilson
 * MIT Licensed
 */

'use strict';

/**
 * Module dependencies.
 * @private
 */

var cookie = require('cookie');
var crc = require('crc').crc32;
var debug = require('debug')('express-session');
var deprecate = require('depd')('express-session');
var parseUrl = require('parseurl');
var uid = require('uid-safe').sync
  , onHeaders = require('on-headers')
  , signature = require('cookie-signature')

var Session = require('./session/session')
  , MemoryStore = require('./session/memory')
  , Cookie = require('./session/cookie')
  , Store = require('./session/store')

// environment

var env = process.env.NODE_ENV;

/**
 * Expose the middleware.
 */

exports = module.exports = session;

/**
 * Expose constructors.
 */

exports.Store = Store;
exports.Cookie = Cookie;
exports.Session = Session;
exports.MemoryStore = MemoryStore;

/**
 * Warning message for `MemoryStore` usage in production.
 * @private
 */

var warning = 'Warning: connect.session() MemoryStore is not\n'
  + 'designed for a production environment, as it will leak\n'
  + 'memory, and will not scale past a single process.';

/**
 * Node.js 0.8+ async implementation.
 * @private
 */

/* istanbul ignore next */
var defer = typeof setImmediate === 'function'
  ? setImmediate
  : function(fn){ process.nextTick(fn.bind.apply(fn, arguments)) }

// 备注：
// 1、sessionId：默认用uid()生成
// 2、session.id：其实就是 req.sessionId

// 请求到达
// 
// 是否初始化过？
// 
// 否：
// 是：


/**
 * Setup session store with the given `options`.
 *
 * @param {Object} [options]
 * @param {Object} [options.cookie] Options for cookie
 * @param {Function} [options.genid]
 * @param {String} [options.name=connect.sid] Session ID cookie name
 * @param {Boolean} [options.proxy]
 * @param {Boolean} [options.resave] Resave unmodified sessions back to the store
 * @param {Boolean} [options.rolling] Enable/disable rolling session expiration
 * @param {Boolean} [options.saveUninitialized] Save uninitialized sessions to the store
 * @param {String|Array} [options.secret] Secret for signing session ID
 * @param {Object} [options.store=MemoryStore] Session store
 * @param {String} [options.unset]
 * @return {Function} middleware
 * @public
 */

function session(options) {
  var opts = options || {}

  // get the cookie options
  // cookie 相关配置，可以参考 “cookie-parser” https://www.npmjs.com/package/cookie-parser
  var cookieOptions = opts.cookie || {}

  // get the session id generate function
  // 生成session id，默认是用 "uid-safe"，也可用自定义算法，前提是生成的id不会冲突。
  var generateId = opts.genid || generateSessionId

  // get the session cookie name
  // session id会存储在cookie里返回给客户端，opts.name 即对应的 cookie 名
  var name = opts.name || opts.key || 'connect.sid'

  // get the session store
  // 存储session的载体，有多种版本实现，比如存到本地文本文件、redis数据库等。
  // 如有必要，可以用你熟悉的数据存储方案，只要按照规范实现了预定义的API即可。
  // 默认是存储在内存（一般用于调试阶段）  
  var store = opts.store || new MemoryStore()  

  // get the trust proxy setting
  // TODO 目前没有用过
  var trustProxy = opts.proxy

  // get the resave session option
  // 如果是true，即使session没有发生任何改变，也会重新保存到 session store 里
  // 默认是true，但新的版本里可能会把默认值设置为false
  // How do I know if this is necessary for my store? 
  // The best way to know is to check with your store if it implements the touch method. 
  // If it does, then you can safely set resave: false. 
  // If it does not implement the touch method and your store sets an expiration date on stored sessions,
  //  then you likely need resave: true.
  // TODO 给更准确的定义
  var resaveSession = opts.resave;

  // get the rolling session option
  // 如果为true，那么每个请求都会发送 set-cookie，将 cookie 的过期时间重置到初始的 max-age
  // 用处：用于延长用户登录态的有效期
  // 默认：false
  // 如果 saveUninitialized === false && rolling === true，那么，
  // 未初始化的 session 不会发送 set-cookie
  var rollingSessions = Boolean(opts.rolling)

  // get the save uninitialized session option
  // 是否保存“未初始化”的session
  // “未初始化”的定义：新的请求，且未修改过（比如通过 req.session.xx = yy 对session进行修改）
  // 默认：true（建议不要用默认值，新版本可能会变成 false ）
  // 备注：如果要实现登录功能，建议设置为false
  var saveUninitializedSession = opts.saveUninitialized

  // get the cookie signing secret
  var secret = opts.secret

  // opts.genid 比如是函数，否则报错
  if (typeof generateId !== 'function') {
    throw new TypeError('genid option must be a function');
  }

  // opts.resave、opts.saveUninitialized 的默认值可能会变，建议显式声明具体的值
  // opts.resave ==> 默认true
  // opts.saveUninitialized ==> 默认true
  if (resaveSession === undefined) {
    deprecate('undefined resave option; provide resave option');
    resaveSession = true;
  }

  if (saveUninitializedSession === undefined) {
    deprecate('undefined saveUninitialized option; provide saveUninitialized option');
    saveUninitializedSession = true;
  }

  // 跟 Session.destroy(callback) 配置使用，可选的值有 "destroy"、"keep"
  // destroy => 请求结束时，session 会销毁
  // keep => 请求结束时，store 里的session会被保存，但请求期间的改动会被忽略（不保存）
  // TODO 实例 + 细节
  if (opts.unset && opts.unset !== 'destroy' && opts.unset !== 'keep') {
    throw new TypeError('unset option must be "destroy" or "keep"');
  }

  // TODO: switch to "destroy" on next major
  var unsetDestroy = opts.unset === 'destroy'

  if (Array.isArray(secret) && secret.length === 0) {
    throw new TypeError('secret option array must contain one or more strings');
  }

  // secret的作用如下：（逆向操作）
  // 1、对session id 对应的cookie进行签名
  // 2、对session id 对应的cookie进行解签名
  // 
  // 
  // 注意，当 secret 为数组时
  // 1、签名：用数组里的第一个secret
  // 2、解签名：遍历 secret 数组，直到其中一个解签名成功
  // 
  // 备注：为什么设计为数组，以下为猜测
  // 假设服务已上线，初始secret为secretA，且当前已有用户登录 ==> 用户浏览器已经保存了服务端设置的cookie（签过名的）
  // 因某些原因，需要更换secret，比如更换成secretB ==> 之前用 secretA 签名cookie 的用户登录态会失效
  // 采用当前设计，则可平滑过渡，新旧secret签名的cookie都可以正常使用，直到旧会话过期，可以完全废弃 secretA
  // 
  if (secret && !Array.isArray(secret)) {
    secret = [secret];
  }

  if (!secret) {
    deprecate('req.secret; provide secret option');
  }

  // notify user that this store is not
  // meant for a production environment
  if ('production' == env && store instanceof MemoryStore) {
    /* istanbul ignore next: not tested */
    console.warn(warning);
  }

  // generates the new session
  // 生成新的session，最终的结果
  // 1、req.sessionId --> session id
  // 2、req.session --> 对应的session实例
  // 3、req.session.cookie --> session关联的cookie实例
  store.generate = function(req){
    
    // 生成session id
    req.sessionID = generateId(req);

    // 创建新的session
    req.session = new Session(req);  
    
    // session 相关的cookie实例
    // 比如要修改cookie的过期时间等，后续可通过 req.session.cookie来操作
    req.session.cookie = new Cookie(cookieOptions);

    // TODO 待探究
    if (cookieOptions.secure === 'auto') {
      req.session.cookie.secure = issecure(req, trustProxy);
    }
  };

  // store 是否实现了 touch方法
  var storeImplementsTouch = typeof store.touch === 'function';

  // register event listeners for the store to track readiness
  var storeReady = true
  store.on('disconnect', function ondisconnect() {
    storeReady = false
  })
  store.on('connect', function onconnect() {
    storeReady = true
  })

  return function session(req, res, next) {
    // self-awareness
    // 已经初始化过 req.session，直接跳过
    if (req.session) {
      next()
      return
    }

    // Handle connection as if there is no session if
    // the store has temporarily disconnected etc
    // 异常处理，比如 redis 突然挂了连不上
    if (!storeReady) {
      debug('store is disconnected')
      next()
      return
    }

    // pathname mismatch
    // cookie 设置了path，如果当前请求的路径不属于path的范围，直接跳过
    // 比如：
    // 1、pathname为 '/oc/v/account/'
    // 2、cookieOptions.path 为 '/oc/v/hello'
    // 那么，当前请求没有权限访问相应的cookie，那么直接跳过
    var originalPath = parseUrl.original(req).pathname;
    if (originalPath.indexOf(cookieOptions.path || '/') !== 0) return next();

    // ensure a secret is available or bail
    // 如果没有声明 secret ，直接抛异常 
    // TODO 例子
    if (!secret && !req.secret) {
      next(new Error('secret option required for sessions'));
      return;
    }

    // backwards compatibility for signed cookies
    // req.secret is passed from the cookie parser middleware
    var secrets = secret || [req.secret];

    var originalHash;
    var originalId;
    var savedHash;
    var touched = false

    // expose store
    req.sessionStore = store;

    // get the session ID from the cookie
    // 从cookie中获取session id（如果之前已经生成过session id的话）
    // 如果没有生成过，返回undefined
    var cookieId = req.sessionID = getcookie(req, name, secrets);

    // set-cookie
    // Execute a listener when a response is about to write headers.
    onHeaders(res, function(){
      if (!req.session) {
        debug('no session');
        return;
      }

      // 是否需要设置cookie
      if (!shouldSetCookie(req)) {
        return;
      }

      // only send secure cookies via https
      // TODO ...
      if (req.session.cookie.secure && !issecure(req, trustProxy)) {
        debug('not secured');
        return;
      }

      // session.touch() 的定义
      // Updates the .maxAge property. 
      // Typically this is not necessary to call, as the session middleware does this for you.
      if (!touched) {
        // touch session
        req.session.touch()
        touched = true
      }

      // set cookie
      setcookie(res, name, req.sessionID, secrets[0], req.session.cookie.data);
    });

    // proxy end() to commit the session
    var _end = res.end;
    var _write = res.write;
    var ended = false;
    res.end = function end(chunk, encoding) {
      if (ended) {
        return false;
      }

      ended = true;

      var ret;
      var sync = true;

      function writeend() {
        if (sync) {
          ret = _end.call(res, chunk, encoding);
          sync = false;
          return;
        }

        _end.call(res);
      }

      function writetop() {
        if (!sync) {
          return ret;
        }

        if (chunk == null) {
          ret = true;
          return ret;
        }

        var contentLength = Number(res.getHeader('Content-Length'));

        if (!isNaN(contentLength) && contentLength > 0) {
          // measure chunk
          chunk = !Buffer.isBuffer(chunk)
            ? new Buffer(chunk, encoding)
            : chunk;
          encoding = undefined;

          if (chunk.length !== 0) {
            debug('split response');
            ret = _write.call(res, chunk.slice(0, chunk.length - 1));
            chunk = chunk.slice(chunk.length - 1, chunk.length);
            return ret;
          }
        }

        ret = _write.call(res, chunk, encoding);
        sync = false;

        return ret;
      }

      // 是否需要销毁session
      // 如需要：1、销毁session 2、返回
      if (shouldDestroy(req)) {
        // destroy session
        debug('destroying');
        store.destroy(req.sessionID, function ondestroy(err) {
          if (err) {
            defer(next, err);
          }

          debug('destroyed');
          writeend();
        });

        return writetop();
      }

      // no session to save
      // 如果没有session，直接返回
      if (!req.session) {
        debug('no session');
        return _end.call(res, chunk, encoding);
      }

      // 如果还没更新 maxAge，自动更新，并把 touched 置为 true
      if (!touched) {
        // touch session
        req.session.touch()
        touched = true
      }

      // 是否需要保存 session 
      // 如需要：save() -> writeTop()，直接返回 -> save() 成功回调 writeend()
      if (shouldSave(req)) {
        req.session.save(function onsave(err) {
          if (err) {
            defer(next, err);
          }

          // 保存后返回
          writeend();
        });

        return writetop();
      } else if (storeImplementsTouch && shouldTouch(req)) {
        // store 是否实现了 Session.touch 方法
        // 如是：touch() -> writetop() -> writeend() -> 返回
        // store implements touch method
        debug('touching');
        store.touch(req.sessionID, req.session, function ontouch(err) {
          if (err) {
            defer(next, err);
          }

          debug('touched');
          writeend();
        });

        return writetop();
      }

      return _end.call(res, chunk, encoding);
    };

    // generate the session
    function generate() {
      
      // store 本身并没有定义 .generate() 这个方法，在中间件初始化的时候动态添加的方法
      store.generate(req);
      
      originalId = req.sessionID;
      
      // 先将 req.session stringify，再计算循环校验和
      originalHash = hash(req.session);
      
      // 把 req.session 的 reload、save 方法包裹一层
      // 作用：日志打印
      wrapmethods(req.session);
    }

    // wrap session methods
    function wrapmethods(sess) {
      var _reload = sess.reload
      var _save = sess.save;

      function reload(callback) {
        debug('reloading %s', this.id)
        _reload.call(this, function () {
          wrapmethods(req.session)
          callback.apply(this, arguments)
        })
      }

      function save() {
        debug('saving %s', this.id);
        savedHash = hash(this);
        _save.apply(this, arguments);
      }

      Object.defineProperty(sess, 'reload', {
        configurable: true,
        enumerable: false,
        value: reload,
        writable: true
      })

      Object.defineProperty(sess, 'save', {
        configurable: true,
        enumerable: false,
        value: save,
        writable: true
      });
    }

    // check if session has been modified
    // 
    // 检查：session是否被修改过，判断依据
    // 1、sessionId是否发生变化（比如 opts.genId 变化）
    // 2、hash是否发生变化（比如 hash 算法发生变化）
    // 
    function isModified(sess) {
      return originalId !== sess.id || originalHash !== hash(sess);
    }

    // check if session has been saved
    // 判断：session是否已经被保存到store里
    // 一般情况下，Session.save 不用主动调用
    // 
    // This method is automatically called at the end of the HTTP response if the session data has been altered (though this behavior can be altered with various options in the middleware constructor). 
    // Because of this, typically this method does not need to be called.
    // 
    function isSaved(sess) {
      return originalId === sess.id && savedHash === hash(sess);
    }

    // determine if session should be destroyed
    // 判断：是否需要销毁session
    function shouldDestroy(req) {
      return req.sessionID && unsetDestroy && req.session == null;
    }

    // determine if session should be saved to store
    // 判断：是否需要把session 保存到 store
    // 
    function shouldSave(req) {
      // cannot set cookie without a session ID
      if (typeof req.sessionID !== 'string') {
        debug('session ignored because of bogus req.sessionID %o', req.sessionID);
        return false;
      }

      return !saveUninitializedSession && cookieId !== req.sessionID
        ? isModified(req.session)
        : !isSaved(req.session)
    }

    // determine if session should be touched
    function shouldTouch(req) {
      // cannot set cookie without a session ID
      if (typeof req.sessionID !== 'string') {
        debug('session ignored because of bogus req.sessionID %o', req.sessionID);
        return false;
      }

      return cookieId === req.sessionID && !shouldSave(req);
    }

    // determine if cookie should be set on response
    // 判断：是否需要在response里面设置cookie
    // 
    // 一、如果没有session id，不设置
    // 
    // 二、如果 cookieId != req.sessionID （比如是未初始化过的请求，那么 cookieId 为 undefined）
    // 1、如果 saveUninitializedSession === true，设置
    // 2、如果“会话被修改过”，比如 
    //     2.1、前后sessionId不一致 （比如切换了 opts.genId 算法），或者
    //     2.2  session id 一致但是 hash不一致（比如切换了hash算法）
    //  那么，设置
    //  
    // 三、...
    function shouldSetCookie(req) {
      // cannot set cookie without a session ID
      if (typeof req.sessionID !== 'string') {
        return false;
      }

      return cookieId != req.sessionID
        ? saveUninitializedSession || isModified(req.session)
        : rollingSessions || req.session.cookie.expires != null && isModified(req.session);
    }

    // generate a session if the browser doesn't send a sessionID
    // req.sessionID 为undefined，则生成session
    if (!req.sessionID) {
      debug('no SID sent, generating session');
      generate();
      next();
      return;
    }

    // generate the session object
    debug('fetching %s', req.sessionID);
    store.get(req.sessionID, function(err, sess){
      // error handling
      if (err) {
        debug('error %j', err);

        if (err.code !== 'ENOENT') {
          next(err);
          return;
        }

        generate();
      // no session
      } else if (!sess) {
        debug('no session found');
        generate();
      // populate req.session
      } else {
        debug('session found');
        store.createSession(req, sess);
        originalId = req.sessionID;
        originalHash = hash(sess);

        if (!resaveSession) {
          savedHash = originalHash
        }

        wrapmethods(req.session);
      }

      next();
    });
  };
};

/**
 * Generate a session ID for a new session.
 *
 * @return {String}
 * @private
 */

function generateSessionId(sess) {
  return uid(24);
}

/**
 * Get the session ID cookie from request.
 *
 * 从 请求中获取 session id 对应的 cookie
 *
 * 
 *
 * @return {string}
 * @private
 */

function getcookie(req, name, secrets) {
  var header = req.headers.cookie;
  var raw;
  var val;

  // read from cookie header
  if (header) {
    var cookies = cookie.parse(header);

    raw = cookies[name];

    if (raw) {
      if (raw.substr(0, 2) === 's:') {
        val = unsigncookie(raw.slice(2), secrets);

        if (val === false) {
          debug('cookie signature invalid');
          val = undefined;
        }
      } else {
        debug('cookie unsigned')
      }
    }
  }

  // back-compat read from cookieParser() signedCookies data
  if (!val && req.signedCookies) {
    val = req.signedCookies[name];

    if (val) {
      deprecate('cookie should be available in req.headers.cookie');
    }
  }

  // back-compat read from cookieParser() cookies data
  if (!val && req.cookies) {
    raw = req.cookies[name];

    if (raw) {
      if (raw.substr(0, 2) === 's:') {
        val = unsigncookie(raw.slice(2), secrets);

        if (val) {
          deprecate('cookie should be available in req.headers.cookie');
        }

        if (val === false) {
          debug('cookie signature invalid');
          val = undefined;
        }
      } else {
        debug('cookie unsigned')
      }
    }
  }

  return val;
}

/**
 * Hash the given `sess` object omitting changes to `.cookie`.
 *
 * 算法分两步：
 * 1、JSON.stringify( sess ) ==> str （将 key 为 cookie 的内容排除）
 * 2、crc( str ) ==> 计算str的循环校验和
 *
 * @param {Object} sess
 * @return {String}
 * @private
 */

function hash(sess) {
  return crc(JSON.stringify(sess, function (key, val) {
    if (key !== 'cookie') {
      return val;
    }
  }));
}

/**
 * Determine if request is secure.
 *
 * @param {Object} req
 * @param {Boolean} [trustProxy]
 * @return {Boolean}
 * @private
 */

function issecure(req, trustProxy) {
  // socket is https server
  if (req.connection && req.connection.encrypted) {
    return true;
  }

  // do not trust proxy
  if (trustProxy === false) {
    return false;
  }

  // no explicit trust; try req.secure from express
  if (trustProxy !== true) {
    var secure = req.secure;
    return typeof secure === 'boolean'
      ? secure
      : false;
  }

  // read the proto from x-forwarded-proto header
  var header = req.headers['x-forwarded-proto'] || '';
  var index = header.indexOf(',');
  var proto = index !== -1
    ? header.substr(0, index).toLowerCase().trim()
    : header.toLowerCase().trim()

  return proto === 'https';
}

/**
 * Set cookie on response.
 *
 * @private
 */

function setcookie(res, name, val, secret, options) {
  // 格式为 s:xx 
  // 其中，xx 为 签名后的 sessionId （签名用的secret为 opts.secret）
  var signed = 's:' + signature.sign(val, secret);

  // options 为 cookie的配置项，比如 path、httpOnly 等
  var data = cookie.serialize(name, signed, options);

  debug('set-cookie %s', data);

  var prev = res.getHeader('set-cookie') || [];
  var header = Array.isArray(prev) ? prev.concat(data) : [prev, data];

  res.setHeader('set-cookie', header)
}

/**
 * Verify and decode the given `val` with `secrets`.
 *
 * @param {String} val
 * @param {Array} secrets
 * @returns {String|Boolean}
 * @private
 */
function unsigncookie(val, secrets) {
  for (var i = 0; i < secrets.length; i++) {
    var result = signature.unsign(val, secrets[i]);

    if (result !== false) {
      return result;
    }
  }

  return false;
}
