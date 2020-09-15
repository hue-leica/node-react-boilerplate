const express =require('express');
const app = express();
const port = 5000;
const bodyParser = require('body-parser');
const { User } = require('./models/user');
const mongoose = require('mongoose');
const config = require('./config/key');
const cookieParser = require('cookie-parser');
const auth = require('./middleware/auth');

app.use(bodyParser.urlencoded({extended: true}));
app.use(bodyParser.json());
app.use(cookieParser());
mongoose.connect(config.mongoURI,
{
    useNewUrlParser: true, useUnifiedTopology:true, useCreateIndex:true, useFindAndModify: false
}).then(()=> console.log('MongoDB Connected...!'))
   .catch(err => console.log(err));
   

app.get('/api/hello', (req,res)=>{
    res.send('Adele Hello~~');
})
app.get('/',(req,res)=> res.send('Hello world!!'));
app.post('/api/users/register', (req,res) => {
    const user = new User(req.body);

    user.save((err, userInfo)=>{
        if(err) return res.json({success: false, err});
    return res.status(200).json({
        success: true
    });
    });
});
app.post('/api/users/login',(req,res)=>{
    User.findOne({ // 몽고 DB에서 찾는 메소드
        email: req.body.email
    },(err,user)=>{
        if(!user){
            return res.json({loginSuccess: false, message : "제공된 이메일에 해당하는 유저가 없습니다."});
        }
        user.comparePassword(req.body.password, (err,isMatch)=>{
            if(!isMatch)
            return res.json({loginSuccess: false, message: "비밀번호가 틀렸습니다."});

            user.generateToken((err,user)=>{
                if(err) return res.status(400).send(err);

                // 토큰을 어디에 저장할지! (쿠키, 로컬스토리지 등) 여기서는 쿠키에다가 한다.
                // 쿠키에 저장하기 위해 cookieParser을 설치한다
                res.cookie("x_auth", user.token)
                    .status(200)
                    .json({loginSuccess: true, userId: user._id});
            });
        });
    }
 );
});

app.get('/api/users/auth', auth, (req, res)=>{
    res.status(200).json({
        _id: req.user._id,
        isAdmin: req.user.role === 0 ? false : true,
        isAuth: true,
        email: req.user.email,
        name: req.user.name,
        lastname: req.user.lastname,
        role: req.user.role,
        image: req.user.image
    });
});

app.get('/api/users/logout', auth, (req, res)=>{
    User.findOneAndUpdate({_id: req.user._id}, {token: ""},
        (err, user)=>{
            if(err) return res.json({success: false, err})
            return res.json({success: true});
        });
});




app.listen(port,()=>console.log(`example app listening on port! ${port}`));

