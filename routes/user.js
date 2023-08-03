const express = require("express");
const connection = require("../connection");
const router = express.Router();

const jwt = require("jsonwebtoken");
const nodemailer = require("nodemailer");
require("dotenv").config();

var auth=require('../service/authentication');
var checkRole=require('../service/checkRole');

router.post("/signup", (req, res) => {
  let user = req.body;
  query = "select email,password,role,status from user where email=?";
  connection.query(query, [user.email], (err, results) => {
    if (!err) {
      if (results.length <= 0) {
        query =
          "insert into user(name,contactNumber,email,password,status,role) values(?,?,?,?,'false','user')";
        connection.query(
          query,
          [user.name, user.contactNumber, user.email, user.password],
          (err, results) => {
            if (!err) {
              res
                .status(200)
                .json({ message: "Email Successfully Registered" });
            } else {
              return res.status(500).json(err);
            }
          }
        );
      } else {
        res.status(400).json({ message: "Email Alredy Exist." });
      }
    } else {
      return res.status(500).json(err);
    }
  });
});

router.post("/login", (req, res) => {
  const user = req.body;
  query = "select email,password,role,status from user where email=?";
  connection.query(query, [user.email], (err, results) => {
    if (!err) {
      if (results.length <= 0 || results[0].password != user.password) {
        return res
          .status(401)
          .json({ message: "Incorrect Username or Password" });
      } else if (results[0].status == "false") {
        return res.status(401).json({ message: "Wait for Admin Appproval" });
      } else if (results[0].password == user.password) {
        const response = {
          email: results[0].email,
          role: results[0].role,
        };
        const accessToken = jwt.sign(response, process.env.ACCESS_TOKEN, {
          expiresIn: "24h",
        });
        return res.status(200).json({ token: accessToken });
      } else {
        return res.status(400).json({ message: "Something went wrong" });
      }
    } else {
      return res.status(500).json(err);
    }
  });
});

var transporter = nodemailer.createTransport({
  service: "gmail",
  auth: {
    user: process.env.EMAIL,
    pass: process.env.PASSWORD,
  },
});

router.post("/forgotPassword", (req, res) => {
  const user = req.body;
  query = "select email,password from user where email=?";
  connection.query(query, [user.email], (err, results) => {
    if (!err) {
      if (!err) {
      } else {
      }
      if (results.length <= 0) {
        return res.status(200).json("Password Sent Succesfully");
      } else {
        var mailOptions = {
          from: process.env.MAIL,
          to: results[0].email,
          subject: "Password by Cafe Management ",
          html: `<h4>Login credential/details for Cafe Management </h4>
                <p><b>Username:</b> ${results[0].email}</p>
                <p><b>Password:</b> ${results[0].password}</p>
                <a href="http://localhost:4200">Click Here to Login</a>
                <br>
                <br>
                <br>
                <br>
                <br>
                <p>Thanks & Regards</p>
                <p>Bipul Kumar</p>
                <p>Cafe Management </p>`,
        };
        transporter.sendMail(mailOptions, function (err, info) {
          if (err) {
            console.log(err);
          } else {
            console.log("Email Sent" + info.response);
          }
        });
      }
    } else {
      return res.status(500).json(err);
    }
  });
});

router.get("/get",auth.authenticateToken,checkRole.checkRole,(req, res) => {
  
  var query =
    "select id,name,email,contactNumber,status from user where role='user'";
  connection.query(query, (err, results) => {
    if (!err) {
      return res.status(200).json(results);
    } else {
      return res.status(500).json(err);
    }
  });
});


router.patch('/update',auth.authenticateToken,(req,res)=>{
    let user=req.body;
    var query="update user set status=? where id=?"
    connection.query(query,[user.status,user.id],(err,results)=>{
        if(!err){
            if(results.affectedRows==0){
                return res.status(404).json({message:"User id doesn't exist"})
            }
            else{
                return res.status(200).json({message:"User Updated Successfully"})
                
            }
        }
        else{
            return res.status(500).json(err);
          }
        })
});


router.get('/checkToken',auth.authenticateToken,(req,res)=>{
    return res.status(200).json({message:"true"})
});


router.post('/changePassword',auth.authenticateToken,(req,res)=>{
  const user=req.body;
  const email=res.locals.email;
  var query="select * from user where email=? and password=?";
  connection.query(query,[email,user.oldPassword],(err,results)=>{
    if(!err){
      if(results.length<=0){
        return res.status(400).json({message:"Incorrect Old Password"});
      }
      else if (results[0].password== user.oldPassword){
        query="update user set password=? where email=?";
        connection.query(query,[user.newPassword,email],(err,results)=>{
          if(!err){

            return res.status(200).json({message:"Password Updated Successfully"});
          }
          else{
            return res.status(500).json(err);

          }
        })
      }
      else{
        return res.status(400).json({message:"Something went wrong. Please try again later."})
      }
    }
    else{
      return res.status(500).json(err);
      
    }
  })
});



module.exports = router;
