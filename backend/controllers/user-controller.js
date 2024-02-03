const User = require('../model/User')
const bcrypt = require('bcryptjs')
const jwt = require('jsonwebtoken')
const signup = async(req,res,next)=>{
    let existingUser;
    const{name,email,password}=req.body
    try {
        existingUser=await User.findOne({email:email})
    } catch (error) {
        return new Error(error)

    }
    if(existingUser){
        return res.status(400).json({message:"User already exists! Login>>"})
    }
    const hashedPassword = bcrypt.hashSync(password)

    const user = new User({
        name,
        email,
        password:hashedPassword
    })


    try {
        await user.save()
    } catch (error) {
        console.log(error)
    }

    return res.status(201).json({message:user})
}

const login = async(req,res,next)=>{
    const{email,password}=req.body
    let existingUser;
    try {
        existingUser=await User.findOne({email:email})
    } catch (error) {
        return new Error(error)
    }
    if(!existingUser){
        return res.status(400).json({message:"User not found. Signup!"})
    }
    const isPasswordCorrect = bcrypt.compareSync(password,existingUser.password)
    if(!isPasswordCorrect){
        return res.status(400).json({message:'Invalid Email or Password'})
    }
    const token = jwt.sign({id:existingUser._id},process.env.JWT_SECRET_KEY,{
        expiresIn:"35s"
    })
    console.log("generated token\n",token);
    if(req.cookies[`${existingUser._id}`]){
        req.cookies[`${existingUser._id}`]=""
    }

    res.cookie(String(existingUser._id),token,{
        path:'/',
        expires: new Date(Date.now()+ 1000*30),
        httpOnly: true,
        sameSite:'lax'
    })

    return res.status(200).json({message:"Successfully Logged In",user:existingUser,token})

}
const verifyToken =(req,res,next)=>{
    const cookies = req.headers.cookie
    const token =cookies.split("=")[1]
    if(!token){
        res.status(404).json({message:"No token found"})
    }
    jwt.verify(String(token),process.env.JWT_SECRET_KEY,(err,user)=>{
        if(err){
            return res.status(400).json({message:"Invalid token"})
        }
        req.id=user.id
    })
    next()
}
const getUser=async(req,res,next)=>{
    const userId=req.id;
    let user;
    try {
        user = await User.findById(userId,"-password")
    } catch (error) {
        return new Error(err)
    }
    if(!user){
        return res.status(404).json({message:"USer Not Found"})
    }
    return res.status(200).json({user})

}

const refershToken =(req,res,next)=>{
    const cookies = req.headers.cookie
    const prevtoken =cookies.split("=")[1]
    if(!prevtoken){
        return res.status(400).json({message:"Couldnt find token"})
    }
    jwt.verify(String(prevtoken),process.env.JWT_SECRET_KEY,(err,user)=>{
        if(err){
            console.log(err);
            return res.status(403).json({message:'Auth is failed'})
        }
        res.clearCookie(`${user.id}`)
        req.cookies[`${user.id}`]=""

        const token = jwt.sign({id:user.id},process.env.JWT_SECRET_KEY,{
            expiresIn:"35s"
        })
        console.log("regen token\n",token);
        res.cookie(String(user.id),token,{
            path:'/',
            expires: new Date(Date.now()+ 1000*30),
            httpOnly: true,
            sameSite:'lax'
        })
        req.id=user.id
        next()
    })
}

const logout=(req,res,next)=>{
    const cookies = req.headers.cookie
    const prevtoken =cookies.split("=")[1]
    if(!prevtoken){
        return res.status(400).json({message:"Couldnt find token"})
    }
    jwt.verify(String(prevtoken),process.env.JWT_SECRET_KEY,(err,user)=>{
        if(err){
            console.log(err);
            return res.status(403).json({message:'Auth is failed'})
        }
        res.clearCookie(`${user.id}`)
        req.cookies[`${user.id}`]=""
        return res.status(200).json({message:"Successfully logged out"})

    })
}

module.exports={signup,login,verifyToken,getUser,refershToken,logout}

