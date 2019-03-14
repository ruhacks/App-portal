const express = require('express');
const router = express.Router();
const bcrypt = require('bcryptjs');
const passport = require('passport');
const sanitize = require('mongo-sanitize');

//User Model
const User = require('../models/Users');

//Login Page
router.get('/login', (req,res)=>res.render("login"));

//Register Page
router.get('/register', (req,res)=>res.render("register"));

//Register Handle
router.post('/register', (req,res)=>{
    const {Fname,Lname, email, password, password2} = req.body;
    let errors = [];

    const sFname = sanitize(Fname).trim();
    const sLname = sanitize(Lname).trim();

    //check required fields
    if(!sFname ||!sLname|| !email || !password || !password2){
        errors.push({msg: "Please fill in all fields"});
    }

    if(password != password2){
        errors.push({msg: 'Passwords Do not match'});
    }

    if(password.length < 6 ){
        errors.push({msg: 'Password should be at least 6 characters'});
    }

    if(errors.length>0){
        res.render('register',{
            errors,
            Fname:sFname,
            Lname:sLname,
            email,
            password,
            password2
        });
    }else{
        // Validation passed
        User.findOne({email: email})
        .then(user =>{
            if(user){
                //USer Exists
                errors.push({msg:"Email is already registered"});
                res.render('register',{
                    errors,
                    Fname: sFname,
                    Lname: sLname,
                    email,
                    password,
                    password2
                });
            }else{
                const newUser = new User({
                    Fname: sFname,
                    Lname: sLname,
                    email,
                    password
                });
                //Hash password
                bcrypt.genSalt(10, (err,salt)=>
                    bcrypt.hash(newUser.password, salt,(err,hash)=>{
                        if(err) throw err;
                        //Set password to hashed
                        newUser.password = hash;
                        //Save user
                        newUser.save()
                            .then(user=>{
                                req.flash('success_msg', "You are now registered!");
                                res.redirect('/users/login');
                            })
                            .catch(err=>console.log(err));
                }))
            }
        });
    }
});

//Login handle
router.post('/login',(req,res, next)=>{
    passport.authenticate('local',{
        successRedirect: '/dashboard',
        failureRedirect: '/users/login',
        failureFlash: true
    })(req,res,next);
});

//Logout handle
router.get('/logout',(req,res)=>{
    req.logout();
    req.flash('success_msg', 'You are logged out');
    res.redirect('/users/login');
})

module.exports = router;