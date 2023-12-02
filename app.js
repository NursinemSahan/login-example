if(process.env.NODE_ENV !== "production"){
    require("dotenv").config();
};
const express = require("express");
const app = express();
const bcrypt = require("bcrypt");
const flash = require("express-flash");
const session = require("express-session");
const methodOverride = require("method-override");

const passport = require("passport");
const initializePassport = require("./passport-config");

initializePassport(
    passport, 
    email=>users.find(user=> user.email === email), 
    id=> users.find(user => user.id===id)
);

app.set("view engine", "ejs");
app.use(express.urlencoded({extended:false}));
app.use(flash());
app.use(session({
    secret : process.env.SESSION_SECRET,
    resave : false,
    saveUninitialized : false
}));
app.use(passport.initialize());
app.use(passport.session())
app.use(methodOverride('_method'));

const users = [];

app.get("/", authenticatedTrue, (req, res)=>{
    res.render("index.ejs", {name : req.user.name });
});

app.get("/login", authenticatedFalse, (req, res)=>{
    res.render("login.ejs");
});

app.get("/register", authenticatedFalse, (req, res)=>{
    res.render("register.ejs");
});

app.post("/register", authenticatedFalse, async (req, res)=>{
    try {
        const hashedPassword = await bcrypt.hash(req.body.password, 10);
        users.push({id: Date.now().toString(),
            name: req.body.name, 
            email: req.body.email, 
            password: hashedPassword}
        );
        res.redirect("/login");    
    } catch (error) {
        res.redirect("/register");
    }

});

app.post("/login", authenticatedFalse, passport.authenticate("local",{
    successRedirect : "/",
    failureRedirect : "/login" ,
    failureFlash : true
}));

app.delete("/logout", (req, res, next)=>{
    req.logout(function(err) {
    if (err) { return next(err); }
    res.redirect('/login');
    });
})


function authenticatedTrue(req, res, next){
    if(req.isAuthenticated()){return next()};
    res.redirect("/login");
}

function authenticatedFalse(req, res, next){
    if(!req.isAuthenticated()){ return next()};
    res.redirect("/");
}

app.listen(3000);