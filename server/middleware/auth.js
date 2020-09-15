const {User} = require('../models/user');

let auth = (req, res, next) => {
    // 인증처리를 하는 곳
    // 클라이언트의 쿠키에서 토큰을 가져온다.
    let token = req.cookies.x_auth;
    // 토큰을 복호화 한 후 해당 _id를 통해 유저를 찾는다.
    User.findByToken(token, (err, user)=>{
        if(err) throw err;
        if(!user) return res.json({isAuth: false, error: false});

        // 인증이 되었으면 로직에서 쓸 수 있도록 token과 user정보를 req에 넣는다.
        req.token = token;
        req.user = user;
        next();
    });
}
module.exports = auth;