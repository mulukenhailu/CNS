require("dotenv").config();
const express=require("express");
const bodyParser=require("body-parser");
const ejs=require("ejs");
const mongoose=require("mongoose");
const session=require("express-session");
const passport=require("passport");
const passportLocalMongoose=require("passport-local-mongoose");
const Otp_algorithm=require("./otp_algorithm.js");
const Des_algorithm=require("./desAlgorithm.js");
const Aes_algorithm=require("./AesAlgorithm");
const GoogleStrategy = require('passport-google-oauth20').Strategy;
const FacebookStrategy = require('passport-facebook').Strategy;
const findOrCreate = require('mongoose-findorcreate');
const OtpCrypto=require("otp-crypto")


const app=express();
app.use(express.static("public"));
app.set("view engine", "ejs");
app.use(bodyParser.urlencoded({extended:true}));

app.use(session({
    secret:"our little secret",
    resave:false,
    saveUninitialized:false
}));

app.use(passport.initialize());
app.use(passport.session());

mongoose.connect("mongodb://localhost:27017/userDB", {useNewUrlParser:true})

const UserSchema= new mongoose.Schema({
    email:String,
    password:String,
    googleId:String,
    facebookId:String
});

UserSchema.plugin(passportLocalMongoose);
UserSchema.plugin(findOrCreate);

const User= new mongoose.model("User", UserSchema)
 
passport.use(User.createStrategy());
passport.serializeUser(function(user, cb) {
    process.nextTick(function() {
      cb(null, { id: user.id, username: user.username });
    });
  });
  
  passport.deserializeUser(function(user, cb) {
    process.nextTick(function() {
      return cb(null, user);
    });
  });

passport.use(new GoogleStrategy({
    clientID: process.env.CLIENT_ID,
    clientSecret: process.env.CLIENT_SECRET,
    callbackURL: "http://localhost:3001/auth/google/entry",
    userProfileURL:"https://www.googleapis.com/oauth2/v3/userinfo"
  },
  function(accessToken, refreshToken, profile, cb) {
    User.findOrCreate({username: profile.displayName, googleId: profile.id }, function (err, user) {
      return cb(err, user);
    });
  }
));

passport.use(new FacebookStrategy({
    clientID: process.env.CLIENT_ID_FB,
    clientSecret: process.env.CLIENT_SECRET_FB,
    callbackURL: "http://localhost:3001/auth/facebook/entry"
  },
  function(accessToken, refreshToken, profile, cb) {
    User.findOrCreate({ facebookId: profile.id }, function (err, user) {
      return cb(err, user);
    });
  }
));

app.get('/auth/google', passport.authenticate('google',
    {
     scope: ['profile'] 
    })
    );

app.get('/auth/google/entry', passport.authenticate('google',
    { 
        failureRedirect: '/register.ejs'
    }),
    function(req, res) {
        res.redirect('/entry');
    });

app.get('/auth/facebook',passport.authenticate('facebook'));
  
  app.get('/auth/facebook/entry', passport.authenticate('facebook',
   { 
    failureRedirect: '/register.ejs'
   }),
    function(req, res) {
      res.redirect('/entry');
    });

app.get("/about", function(req, res){
    res.render("about");
});

app.get("/", function(req, res){
    res.render("./login/login.ejs");
});

app.get("/register", function(req, res){
    res.render("register.ejs");
});

app.post("/back_otp", function(req, res){
    if (req.body.btn === "otp_enc"){
        res.render("./otp/otp.ejs")
    }
    if (req.body.btn === "des_encry"){
        res.render("./triple_des/des.ejs")
    }
    if (req.body.btn === "AES"){
        res.render("./AES/Aes.ejs")
    }
    if (req.body.Reg === "reg_back"){
        res.render("./login/login.ejs");
    }
});

app.get("/LogOut", function(req, res){
    req.logout(function(err) {
        if (err) { 
            console.log(err);
        }
        res.redirect('/');
      });
});

app.get("/licenseDES", function(req, res){
    res.render("./triple_des/license");
});
app.get("/licenseAES", function(req, res){
    res.render("./AES/license");
});
app.get("/licenseOtp", function(req, res){
    res.render("./otp/license");
});

app.get("/entry", function(req, res){
    if (req.isAuthenticated()){
        res.render("entry");
    }
    else{
        res.redirect("/register")
    }
});

app.post("/entry", function(req, res){
    if (req.isAuthenticated()){
        res.render("entry");
    }
    else{
        res.redirect("/register")
    }
});

app.post("/main", function(req, res){
    const user= new User({
        username:req.body.username,
        password:req.body.password
    });

    req.login(user, function(err){
        if(err){
            console.log(err);
        }else{
            passport.authenticate("local")(req, res, function(){
                res.redirect("/entry");
            });
        }
    });
 });

app.post("/register", function(req, res){
    User.register({username:req.body.username}, req.body.password, function(err, user){
        if(err){
            console.log(err)
            res.redirect("/register")
        }
        else{
            passport.authenticate("local")(req, res, function(){
                res.redirect("/entry");
            });
        }
    })
    if (req.body.name === "Back_M"){
        res.render("./login/login.ejs");
    }
});

app.post("/", function(req, res){
    if (req.body.btn === "otp"){
        res.render("./otp/otp.ejs")
    }
    if (req.body.btn === "3des"){
        res.render("./triple_des/des.ejs")
    }
    if (req.body.btn === "aes"){
        res.render("./AES/Aes.ejs")
    }
    if (req.body.btn === "LogOut"){
        req.logout(function(err) {
            if (err) { 
                console.log(err);
            }
            res.redirect('/');
          });
    }
});
app.post("/otp.ejs", Otp_algorithm);
app.post("/des.ejs", Des_algorithm);
app.post("/Aes.ejs", Aes_algorithm);
 
app.listen(3001)