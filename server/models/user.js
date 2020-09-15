const mongoose = require('mongoose');
const bcrypt = require('bcrypt');
const saltRounds = 10; // salt값을 10자리로 !
const jwt = require('jsonwebtoken');

const userSchema = mongoose.Schema({
    name:{
        type: String,
        maxlength: 50
    },
    email:{
        type: String,
        trim: true, // 해당 값 입력시 빈칸은 없애주는 역할! 
        unique: 1
    },
    password:{
        type: String,
        minlength:5
    },
    lastname: {
        type: String,
        maxlength: 50
    },
    role:{
        type: Number,
        default: 0
    },
    image: String,
    token: {
        type : String,
    },
    tokenExp: {
        type: Number
    }
});

 // user.save()하기 전에 실시
userSchema.pre('save',function(next){
    var user = this; // 상단의 객체를 가리킴
    // password가 변경될 때만 암호화 실행!
    if(user.isModified('password'))
    {
        bcrypt.genSalt(saltRounds,function(err, salt){
            if(err) return next(err); // error나면 바로 save로 진행
            bcrypt.hash(user.password,salt,function(err, hash){
                if(err) return next(err);
                user.password = hash;
                next();
            });
        });
    }else{
        next();
    }
});

userSchema.methods.comparePassword = function(plainPassword, cb){
    bcrypt.compare(plainPassword, this.password, function(err, isMatch){
        if(err) return cb(err);
        cb(null,isMatch);
    });
};

userSchema.methods.generateToken = function(cb){
    var user = this;

    var token = jwt.sign(user._id.toHexString(), 'secretToken'); //user._id + '문자열'로 토큰을 만듬!
    user.token = token;
    user.save(function(err,user){
        if(err) return cb(err);
        cb(null,user);
    })
}

userSchema.statics.findByToken = function(token, cb){
    var user = this;
    // 복호화
    jwt.verify(token, 'secretToken', function(err, decoded){
        // 유저 id를 이용해서 유저를 찾기
        // 클라이언트에서 가져온 token과 DB에 보관된 토큰이 일치하는지 확인
        user.findOne({
            "_id": decoded,
            "token": token }
            ,function(err,user){
                if(err) return cb(err);
                cb(null,user);
            });
    });
}
const User = mongoose.model('User',userSchema);
module.exports = {User}