const express = require('express');
const expressLayouts = require('express-ejs-layouts');
const mongoose = require('mongoose');
const passport = require('passport');
const flash = require('connect-flash');
const session = require('express-session');

const app = express();

//Passport config
require('./config/passport')(passport)

//Mongodb cluster config
const db = require('./config/keys').MongoURI;

//connect to db
mongoose.connect(db, {useNewUrlParser: true})
    .then(()=>console.log("Mongodb connected..."))
    .catch(err=>console.log(err));

//EJS
app.use(expressLayouts);
app.set('view engine', 'ejs');

//bodyparser
app.use(express.urlencoded({extended: false}));

//Express session middleware
app.use(session({
    secret: 'ruhacks',
    resave: true,
    saveUninitialized: true,
}));

//Passport middleware
app.use(passport.initialize());
app.use(passport.session());

//Connect flash
app.use(flash());

//Gloabl Vars
app.use((req,res,next)=>{
    res.locals.success_msg = req.flash('success_msg');
    res.locals.error_msg = req.flash('error_msg');
    res.locals.error = req.flash('error');
    next();
});

//Routers
app.use('/', require('./routes/index'));
app.use('/users', require('./routes/users'));



const PORT = process.env.PORT || 4001;

app.listen(PORT, console.log(`Server started on port ${PORT}`));

