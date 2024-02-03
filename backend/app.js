const express = require('express')
const mongoose = require('mongoose')
const router = require('./routes/user-routes')
const cookieParser =require("cookie-parser")
const cors = require('cors')
require('dotenv').config()

const app = express()
app.use(cors({credentials:true,origin:"http://localhost:3000"}))
app.use(cookieParser())
app.use(express.json())
app.use('/api',router)

const url = process.env.MONGODB_URL
mongoose.connect(url).then(()=>{
    app.listen(process.env.PORT);
    console.log("Database connected")
}).catch((err)=>{
    console.log(err)
})