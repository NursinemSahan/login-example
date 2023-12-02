const bcrypt = require("bcrypt");

const localStrategy =  require("passport-local").Strategy

function initialize(passport, getUserByEmail, getUserById){
    const authenticateUser = async (email, password, done)=>{
        const user = getUserByEmail(email);
        if(user==null){return done(null, false, {message: "No user has found!"})};
        try {
            if(await bcrypt.compare(password, user.password)){
            return done(null, user, {message: "Authentication successful!"});}
            else{
                return done(null, false, {message: "Wrong Password"})
            }
        }
        catch (err) {
            done(err, false, {message: "An error has occured!"})
        }
    }
    passport.use(new localStrategy({usernameField: 'email'}, authenticateUser))

    passport.serializeUser((user, done)=>{
        done(null, user.id);
    })
    passport.deserializeUser((id, done)=>{
        return done(null,getUserById(id));
    })

}

module.exports = initialize;