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
const fileData 