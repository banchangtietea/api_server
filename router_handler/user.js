// 导入数据库操作模块
const db =  require('../db/index')
// 导入 bcryptjs 这个包  （ 加密用的 ）
const bcrypt = require('bcryptjs')
// 导入配置文件
const config =  require('../config')

// 注册新用户的处理函数
exports.regUser = (req, res) => {
  // 接收表单数据
  const userinfo = req.body
  // 判断数据是否合法
  // if (!userinfo.username || !userinfo.password) {
  //   return res.send({ status: 1, message: '用户名或密码不能为空！' })
  // }

  // 定义SQL语句，查询用户名是否被占用
  const sqlStr = `select * from ev_users where username=?`
  db.query(sqlStr, userinfo.username, (err, results) => {
    // 执行 SQL 语句失败
    if(err){
      // return res.send({ status: 1, message: err.message })
      return res.cc(err)
    }
    // 判断用户名是否被占用
    if( results.length > 0 ) {
      // return res.send({ status: 1, message: '用户名被占用，请更换其它用户名' })
      return res.cc('用户名被占用，请更换其他用户名')
    }
    // 调用 bcrypt.hashSync() 对密码进行加密
    userinfo.password = bcrypt.hashSync(userinfo.password, 10)

    // 定义插入新用户的 SQL 语句
    const sql = 'insert into ev_users set ?'
    // 调用 db.query() 执行 SQL 语句
    db.query(sql, { username: userinfo.username, password: userinfo.password }, ( err, results) =>{
      // 判断 SQL 语句是否执行成功
      // if(err) return res.send({ status: 1, message: err.message })
      if(err) return res.cc(err)
      // 判断影响行数是否为 1
      // if(results.affectedRows !== 1 ) return res.send({ status: 1, message: '注册用户失败，请稍后再试！' })
      if( results.affectedRows !== 1) return res.cc('注册用户失败，请稍后再试！')
      // 注册用户成功
      // res.send({ status: 0, message: '注册成功!'})
      res.cc('注册成功！', 0)
    })
  })
  // res.send('reguser OK')
}

// 登录的处理函数
exports.login = (req, res) => {
  // 接收表单数据
  const userinfo =  req.body
  const sql = `select * from ev_users where username=?`
  db.query(sql, userinfo.username, (err, results) => {
    // 执行 SQL 语句失败
    if(err) return res.cc(err)
    // 执行 sql 语句成功，但是查询到数据条数不等于1
    if(results.length !==1) return res.cc('登录失败！')

    // TODO: 判断用户输入的登录密码是否和数据库中的密码一致
    // 拿着用户输入的密码，和数据库中存储的密码进行对比
    const compareResult = bcrypt.compareSync(userinfo.password, results[0].password)
    // 如果对比的结果等于 false，则证明用户输入的密码错误  !compareResult = compareResult===false
    if (!compareResult) return res.cc('登录失败！')
    
    // TODO: 在服务器端生成 Token 的字符串
    // 剔除
    const user = { ...results[0], password:'', user_pic: '' }
    // console.log(user);
    // 用这个包生成 Token 字符串
    const jwt =  require('jsonwebtoken')
    // 生成 Token 字符串
    const tokenStr = jwt.sign(user, config.jwtSecretKey,{
      expiresIn: '10h', // token 有效期为 10个小时
    })
    
    // 将生成的Token字符串响应给客户端
    res.send({
      status: 0,
      message: '登录成功！',
      // 为了方便客户端使用 Token, 在服务器端直接拼接上 Bearer 的前缀
      token: 'Bearer' + tokenStr
    })
    // res.send('login OK')
    


  })
  
}