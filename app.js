// jshint esversion:6
require('dotenv').config()
const express=require("express")
const bodyParser = require("body-parser")
const ejs=require("ejs")
const mongoose=require("mongoose")
const bcrypt=require("bcrypt")
const session=require("express-session")
const passport=require("passport")
const flash = require('connect-flash')
const passportLocalMongoose = require("passport-local-mongoose");
const findOrCreate = require("mongoose-findorcreate");
const LocalStrategy=require("passport-local").Strategy;
const GoogleStrategy = require('passport-google-oauth20').Strategy;
const FacebookStrategy = require('passport-facebook').Strategy;



const app=express();
app.use(express.urlencoded({extended:false}))  //Not using bodyParser, using Express in-built body parser instead
app.set("view engine","ejs")
app.use(express.static("public"))
app.use(bodyParser.urlencoded({extended: true}));

app.use(session({
    secret:"Justarandomstring.",
    resave:false,
    saveUninitialized:false
}))

app.use(passport.initialize());
app.use(passport.session());
app.use(flash());

mongoose.connect("mongodb://127.0.0.1:27017/userDB")
const userSchema= new mongoose.Schema({
    username : String,
    password : String,
    googleId: String,
    secrets: String
});
userSchema.plugin(passportLocalMongoose);
userSchema.plugin(findOrCreate);

const User=new mongoose.model("User",userSchema)

//Creating Local Strategy. passport-local-mongoose 3 lines of code for Strategy, 
//Serialiazation, Deserialization not working due to recent changes in Mongoose 7
passport.use(new LocalStrategy((username,password,done)=>{  //done is a callback function
    try{
        User.findOne({username:username}).then(user=>{
            if (!user){
                return done(null,false, {message:"Incorrect Username"})
            }
            //using bcrypt to encrypt passoword in register post route and compare function in login post round. 
            //login post route will check here during authentication so need to use compare here  
            bcrypt.compare(password,user.password,function(err,result){ 
                if (err){
                    return done(err)
                }
                
                if (result) {
                    return done(null,user)
                }
                else {
                    return done (null,false, {message:"Incorrect Password"})
                }
            })
            
        })
    }
    catch (err){
        return done(err)
    }
    
}))
//serialize user
passport.serializeUser(function(user, done) {
    done(null, user.id);
});

//deserialize user  
passport.deserializeUser(function(id, done) {
    console.log("Deserializing User")
    try {
        User.findById(id).then(user=>{
            done(null,user);
        })
    }
    catch (err){
        done(err);
    }
});

passport.use(new GoogleStrategy({
    clientID: process.env.GOOGLE_CLIENT_ID,
    clientSecret: process.env.GOOGLE_CLIENT_SECRET,
    callbackURL: 'http://localhost:3000/auth/google/secrets'
  },
  async function (accessToken, refreshToken, profile, done) {
    try {
      console.log(profile);
      // Find or create user in your database
      let user = await User.findOne({ googleId: profile.id });
      if (!user) {
        // Create new user in database
        const username = Array.isArray(profile.emails) && profile.emails.length > 0 ? profile.emails[0].value.split('@')[0] : '';
        const newUser = new User({
          username: profile.displayName,
          googleId: profile.id
        });
        user = await newUser.save();
      }
      return done(null, user);
    } catch (err) {
      return done(err);
    }
  }
));

  
passport.use(new FacebookStrategy({
    clientID: process.env.FACEBOOK_CLIEND_ID,
    clientSecret: process.env.FACEBOOK_CLIENT_SECRET,
    callbackURL: 'http://localhost:3000/auth/facebook/secrets'
  },
  async function (accessToken, refreshToken, profile, done) {
    try {
      console.log(profile);
      // Find or create user in your database
      let user = await User.findOne({ facebookId: profile.id });
      if (!user) {
        // Create new user in database
        const newUser = new User({
          username: profile.displayName,
          facebookId: profile.id
        });
        user = await newUser.save();
      }
      return done(null, user);
    } catch (err) {
      return done(err);
    }
  }
));



//get routes
app.get("/",function(req,res){
    res.render("home")
})

app.get('/auth/google',
  passport.authenticate('google', { scope: ['profile'] }));

app.get('/auth/google/secrets', 
  passport.authenticate("google", { failureRedirect: '/login'}),
  function(req, res) {
    // Successful authentication, redirect home.
    res.redirect("/secrets");
  });

app.get('/auth/facebook',
  passport.authenticate('facebook'));

app.get('/auth/facebook/secrets',
  passport.authenticate('facebook', { failureRedirect: '/login' }),
  function (req, res) {
    // Successful authentication, redirect to secrets page.
    res.redirect('/secrets');
  });


app.get("/login",function(req,res){
    res.render("login");
    
})

app.get("/register",function(req,res){
    res.render("register")
    
})

app.get("/secrets",function(req,res){
    User.find({secrets : {$ne: null}}).then(
    (found)=>{
        console.log(found);
        res.render("secrets", {userWithSecrets: found});
    }
    )
})


app.get("/submit", function(req, res){
    
    if (req.isAuthenticated()){
        res.render("submit")
    }
    else {
        res.redirect("/login")
    }
});

app.get("/logout",function(req,res){
    req.logout(function(err){
        if(err){
            console.log(err)
        }
        res.redirect("/");
    });
    
})

//post routes
app.post("/register",function(req,res){
    bcrypt.hash(req.body.password,10,function(err,hash){  //10 is SaltRounds
        if (err){
            console.log(err)
        }
        const user= new User ({
            username:req.body.username,
            password:hash
        })
        user.save()
        
        passport.authenticate('local')(req,res,()=>{res.redirect("/secrets")}) 
    })
})   



app.post('/login',passport.authenticate('local',
    { successRedirect:"/secrets", failureRedirect: '/login', failureFlash:true}
));

app.post("/submit",function(req, res){
    const submittedSecret = req.body.secret;
    
    User.findById(req.user.id).then(
        (founduser)=>{
            if(founduser){
                founduser.secrets = submittedSecret;
                // console.log(founduser.secrets);
                founduser.save().then(()=>{
                res.redirect("/secrets")
                }).catch((err)=>{
                    console.log(err);
                })
            }
        })
    });

//listen
app.listen(3000, ()=> {
    console.log("Server Running on Port 3000")
})