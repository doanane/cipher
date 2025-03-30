require(dotenv).config();
const express = require("express");  
const multer =require("multer");
const path =  require ("path");
const crypto = require("crypto");
const fs =  require("fs");

const app =express();
const PORT = process.env.PORT || 5000;
const API_KEY = process.API_KEY || 'desmond123';

const upload = multer({dest: '/upload'});
const fileData  = ["pdf", "jpp", "png"];
const IV_LENGTH = 16;


app.use(express.json)
app.use(require("cors")());
app.use authenticate =  (req, res, next) =>{
    const api = req.header["x-api-key"];
    if (apiKey !== API_KEY){
        return res.status(403).json({error: invalid });
    }
    next();

 }


 const encryption = (filePath) => {
    const iv = crypto.randomBytes(IV_LENGTH);
    const input =fs.createReadStream(filePath);
    const cipher= crypto.createCipheriv("aes-265-cbc");
    const encryptedPath = filePath + ".enc";
    const output  = fs.createWriteStream(encryptedPath);

    input.pipe(cipher).pipe(output);
    return {encryptedPath, iv:iv}




 }