var passport = require('passport');
var LocalStrategy = require('passport-local').Strategy;
var Users = require('./models/user');
var JwtStrategy = require('passport-jwt').Strategy;
var ExtractJwt = require('passport-jwt').ExtractJwt;
var jwt = require('jsonwebtoken');

var config = require('./config');

exports.local = passport.use(new LocalStrategy(Users.authenticate()));
passport.serializeUser(Users.serializeUser());
passport.deserializeUser(Users.deserializeUser());

exports.getToken = function(user) {
    return jwt.sign(user, config.secretKey, {
        expiresIn: 3600
    });
};

var opts = {};
opts.jwtFromRequest = ExtractJwt.fromAuthHeaderAsBearerToken();
opts.secretOrKey = config.secretKey;

exports.jwtPassport = passport.use(new JwtStrategy(opts, (jtw_payload, done) => {
    console.log("JWT payload: ", jtw_payload);
    Users.findOne({ _id: jtw_payload._id }, (err, user) => {
        if(err) {
            return done(err, false);
        } else if(user) {
            return done(null, user);
        } else {
            return done(null, false);
        }
    });
}));

exports.verifyUser = passport.authenticate('jwt', { session: false });