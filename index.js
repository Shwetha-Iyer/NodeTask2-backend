const express = require("express");
const mongodb = require("mongodb");
const jwt = require("jsonwebtoken");
const nodemailer = require("nodemailer");
const cors = require("cors");
const bcrypt = require("bcrypt");
require("dotenv").config();
const app = express();
const port = process.env.PORT || 3100;
const mongoClient = mongodb.MongoClient;
app.use(express.json());
const dbURL = process.env.DB_URL;
const objectId = mongodb.ObjectID;
app.use(cors());
const URL = "https://sleepy-banach-945fb0.netlify.app/";

app.get("/",(req,res)=>{
    res.send(200).send("Hey There! This page works");
});
app.post("/login",async(req,res)=>{
    try{
        let client = await mongoClient.connect(dbURL);
        let db = client.db("myDB");

        let check = await db.collection("login").findOne({email:req.body.email});
        if(check){
            let isValid = await bcrypt.compare(req.body.password,check.password);
            if(isValid){
                res.status(200).send("Login success");
            }
            else{
                res.status(401).send("Wrong password!");
            }
        }
        else{
            res.status(404).send("Email does not exist!");
        }
    }
    catch (error) {
        console.log(error);
        res.status(500).json({
            message: "Internal Server Error",
        });
    }
});


app.post("/forgot",async(req,res)=>{
    try{
        let client = await mongoClient.connect(dbURL);
        let db = client.db("myDB");
        let check = await db.collection("login").findOne({email:req.body.email});
        if(check){
            let p_token = await jwt.sign({email: req.body.email},process.env.T_KEY);     
            await db.collection("login").updateOne({email:req.body.email},{$set:{token:p_token}});
            let transporter = nodemailer.createTransport({
                host: "smtp.office365.com",
                service:"hotmail",
                port: 587,
                secure: false, // true for 465, false for other ports
                auth: {
                    user: process.env.USER, // generated ethereal user
                    pass: process.env.PASS, // generated ethereal password
                  },
              });
            let info = await transporter.sendMail({
                from: 'shwetha.iyer@hotmail.com', // sender address
                to: req.body.email, // list of receivers
                subject: "Password Reset link", // Subject line
                text: `Hello, Please click on the link to reset your password ${URL+p_token}`, // plain text body 
              });
              console.log("Message sent: %s", info.messageId);
              console.log("Preview URL: %s", nodemailer.getTestMessageUrl(info));
            
            res.status(200).send(p_token);
        }
        else{
            res.status(404).send("Email does not exist!");
        }
    }
    catch (error) {
        console.log(error);
        res.status(500).json({
            message: "Internal Server Error",
        });
    }
});

app.get("/resetpwdcheck/:token", async(req,res)=>{
    try{
        let client = await mongoClient.connect(dbURL);
        let db = client.db("myDB");
        let check = await db.collection("login").findOne({token:req.params.token});
        if(check)
        res.status(200).send("exists");
        else
        res.status(404).send("cant find token");
    }
    catch (error) {
        console.log(error);
        res.status(500).json({
            message: "Internal Server Error",
        });
    }
});

app.put("/resetpwd/:token", async(req,res)=>{
    try{
        let client = await mongoClient.connect(dbURL);
        let db = client.db("myDB");
        let salt = await bcrypt.genSalt(10);
        let hash = await bcrypt.hash(req.body.password,salt);
        req.body.password = hash;
        await db.collection("login").updateOne({token:req.params.token},{$set:{password:req.body.password},$unset:{token:1}});
        res.status(200).send("password is reset");
    }
    catch (error) {
        console.log(error);
        res.status(500).json({
            message: "Internal Server Error",
        });
    }
});

app.post("/signup", async(req,res)=>{
    try{
        let client = await mongoClient.connect(dbURL);
        let db = client.db("myDB");
        let salt = await bcrypt.genSalt(10);
        let hash = await bcrypt.hash(req.body.password,salt);
        req.body.password = hash;
        await db.collection("login").insertOne({email:req.body.email,password:req.body.password});
        res.status(200).send("New user inserted");
    }
    catch (error) {
        console.log(error);
        res.status(500).json({
            message: "Internal Server Error",
        });
    }
});

app.listen(port, () => console.log("App index.js inside Task is running on port:", port));