const express=require('express');
const cors=require('cors');
const MongoClient=require('mongodb').MongoClient;
const bodyParser = require('body-parser');
const passport = require('passport');
const LocalStrategy = require('passport-local').Strategy;
const Joi = require('joi');
const bcrypt = require('bcryptjs');
const cookieParser=require('cookie-parser');
const session=require('express-session');
const MongoStore = require('connect-mongo')(session);
const salt = bcrypt.genSaltSync(10);
const app=express();
const corsOptions = {
    origin: 'http://localhost:3000',
    optionsSuccessStatus: 200 
}
app.use(function (req, res, next) {

    // Website you wish to allow to connect
    res.setHeader('Access-Control-Allow-Origin', 'https://localhost:3000');

    // Request methods you wish to allow
    res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS, PUT, PATCH, DELETE');

    // Request headers you wish to allow
    res.setHeader('Access-Control-Allow-Headers', 'X-Requested-With,content-type');

    // Set to true if you need the website to include cookies in the requests sent
    // to the API (e.g. in case you use sessions)
    res.setHeader('Access-Control-Allow-Credentials', true);

    // Pass to next layer of middleware
    next();
});
app.use(cors(corsOptions));
app.use(cookieParser());
app.use(session({
    secret: 'Akhie',
    resave: false,
    saveUninitialized: false,
    store: new MongoStore({ url: 'mongodb://127.0.0.1:27017/Expense' }),
    cookie: {
        secure: true 
    }
  }))
app.use(passport.initialize());
app.use(passport.session());
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));
app.post('/register',(req,res,next)=>{
    const schema=Joi.object().keys({
        firstName :Joi.string().trim().min(1).regex(/^[A-Za-z]{1,}$/).required(),
        lastName  :Joi.string().trim().min(1).regex(/^[A-Za-z]{1,}$/).required (),
        email     :Joi.string().trim().email().
        regex(/^(([^<>()\[\]\.,;:\s@\"]+(\.[^<>()\[\]\.,;:\s@\"]+)*)|(\".+\"))@(([^<>()[\]\.,;:\s@\"]+\.)+[^<>()[\]\.,;:\s@\"]{2,})$/i).required(),
        password  :Joi.string().trim().regex(/^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{8,}$/).required() 
    })
    Joi.validate(req.body , schema ,(err,value)=>{
        if(err){
            res.json({
                success:false,
                message:err.message 
        });
        return next();
        }
    })

    MongoClient.connect('mongodb://127.0.0.1:27017/',{ useNewUrlParser: true },(err,db)=>{
        if(err){
            res.send({ success: false, message: "Internal DB Error." });
        }
        const database=db.db('Expense');
        database.collection('users').findOne({email:req.body.email},(err,response)=>{
            if(err || !response){
                bcrypt.hash(req.body.password, salt, function(err, hash) {
                    if(err) {
                        res.send({ success: false, message: "Internal DB Error." });
                    }
                    const dataObject={
                        firstName:req.body.firstName,
                        lastName:req.body.lastName,
                        email:req.body.email,
                        password:hash
                    }
                    database.collection('users').insertOne(dataObject,(err,responseData)=>{
                        if(err){
                            res.send({ success: false, message: "Internal DB Error." });
                        }else{
                            res.send({success : true, message:'Registered successfully'})
                        }
                    })
                });
            }else{
                res.send({
                    success:false,
                    message:'user already exists' 
                });
            }
        })
    })
});


app.post('/LoginMethod',(req,res)=>{
    const schema=Joi.object().keys({
        email:Joi.string().trim().email().required(),
        password:Joi.string().trim().required()
    })
    Joi.validate(req.body , schema ,(err,value)=>{
        if(err){
            res.send({
                success:false,
                message:err.message 
        });
        return next();
        }
    })
    MongoClient.connect('mongodb://127.0.0.1:27017/',{ useNewUrlParser: true },(err,db)=>{
        if(err){
            res.send({ success: false, message: "Internal DB Error." });
        }
        const database=db.db('Expense');
        database.collection('users').findOne({email:req.body.email},(err,response)=>{
              if(err || !response){
                res.send({
                    success:false,
                    message:'Email is not registered' 
                });
              }else if(response){
                bcrypt.compare(req.body.password, response.password).then(function(responceValue) {
                    if(responceValue){
                        req.session.user=req.body.email;
                        const userId=response._id;
                        req.logIn(userId,(errorValue)=>{
                            res.send({
                                success:true,
                                message:'Login successfull',
                                firstName:response.firstName,
                                lastName:response.lastName,
                                email:response.email,
                                Authentication:req.isAuthenticated(),
                                user_id:req.user

                            });
                        })
                    }else{
                        res.send({
                            success:false,
                            message:'Invalid Username or Password'
                        })
                    }
                });
              }
        })
    })
})



app.get('/getAuthentication',authenticationMiddleware(),(req,res)=>{
    res.send({
        Authentication:req.isAuthenticated()
    });
})

function authenticationMiddleware () {  
	return (req, res, next) => {
        console.log(req.session);
        console.log(req.isAuthenticated());

	    if (req.isAuthenticated()){ 
            next();
    }else{
        res.send({
            Authentication:req.isAuthenticated()
        });
    }
	}
}

passport.use(new LocalStrategy(function(username,password,done){
const schema=Joi.object().keys({
        username:Joi.string().trim().email().required(),
        password:Joi.string().trim().required()
    })
    Joi.validate({username :username,password : password },schema ,(err,value)=>{
        if(err){
        //     res.send({
        //         success:false,
        //         message:err.message 
        // });
        done(null,false);
        }
    })
    MongoClient.connect('mongodb://127.0.0.1:27017/',{ useNewUrlParser: true },(err,db)=>{
        if(err){
            // res.send({ success: false, message: "Internal DB Error." });
            // done(null,{ success: false, message: "Internal DB Error." });
           return  done(null,false);
        }
        const database=db.db('Expense');
        database.collection('users').findOne({email:username},(err,response)=>{
              if(err || !response){
                // res.send({
                //     success:false,
                //     message:'Email is not registered' 
                // });
                // done(null,{ success: false, message: 'Email is not registered' });
                return  done(null,false);
              }else if(response){
                bcrypt.compare(password, response.password).then((responceValue)=> {
                    if(responceValue){
                        // req.session.user=req.body.email;
                        // const userId=response._id;
                        // req.logIn(userId,(errorValue)=>{
                            // res.send({
                            //     success:true,
                            //     message:'Login successfull',
                            //     firstName:response.firstName,
                            //     lastName:response.lastName,
                            //     email:response.email,
                            //     Authentication:req.isAuthenticated(),
                            //     user_id:req.user

                            // });
                        
                            return done(null,{
                                firstName:response.firstName,
                                lastName:response.lastName,
                                email:response.email
                        })
                    }else{
                        // done(null,{
                        //     success:false,
                        //     message:'Invalid Username or Password'
                        // })
                        return done(null,false);
                        // res.send({
                        //     success:false,
                        //     message:'Invalid Username or Password'
                        // })
                    }
                });
              }
        })
    })

}))

passport.serializeUser(function(userid, done) {
    done(null, userid);
  });
  
  passport.deserializeUser(function(userid, done) {
      done(null, userid);
  });

  app.post('/login',passport.authenticate('local'),(req,res)=>{
res.send({
   success:true
})
})

app.listen(3002,()=>{
    console.log('server listening at 3002');
})