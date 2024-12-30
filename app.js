const Express=require("express")
const Mongoose=require("mongoose")
const Cors=require("cors")
const Bcrypt=require("bcrypt")
const Jwt=require("jsonwebtoken")
const userModel = require("./models/users")
const postModel = require("./models/post")

const app=Express()
app.use(Cors())
app.use(Express.json())

Mongoose.connect("mongodb+srv://shilpa:shilpa123@cluster0.qb2ryzy.mongodb.net/blogappDB?retryWrites=true&w=majority&appName=Cluster0")
app.post("/signup",async(req,res)=>{
    //password encryption
    let input=req.body
    let hashedpassword=Bcrypt.hashSync(req.body.password,10)
    req.body.password=hashedpassword
    

    //email existence checking
    userModel.find({email:req.body.email}).then(
        (items)=>{
    
            if (items.length>0) {
                res.json({"status":"email id already exists"})
            } else {
                let result=new userModel(input)
                result.save()
               res.json({"status":"success"})
            }
        }
       ).catch(
        (error)=>{
            console.log(error.message)
        }) })

app.post("/signin",async(req,res)=>{
    let input=req.body
    let result=userModel.find({email:req.body.email}).then(
        (items)=>{
            if (items.length>0) {
                const passwordValidator=Bcrypt.compareSync(req.body.password,items[0].password)
                if (passwordValidator) {
                    Jwt.sign({email:req.body.email},"mytoken",{expiresIn:"1d"},(error,token)=>{
                        if (error) {
                            res.json({"status":"error password","errorMessage":error})
                        } else {
                            res.json({"status":"success","token":token,"userId":items[0]._id})
                        }
                    })
                } else {
                    res.json({"status":"incorrect password"})
                }
            } else {
                res.json({"status":"invalid email id"})
            }
        }
    )
})

app.post("/create",(req,res)=>{
    let input=req.body
    let token=req.headers.token
    Jwt.verify(token,"mytoken",(error,decoded)=>{
        if (decoded && decoded.email) {
            let result=new postModel(input)
            result.save()
            res.json({"status":"success"})
        } else {
            res.json({"status":"Invalid authentication"})
        }
    })
})

app.post("/viewall", async(req,res)=>{
    let token=req.headers.token
    Jwt.verify(token,"mytoken",async(error,decoded)=>{
        if (decoded) {
            postModel.find().then(
                (items)=>{
                    res.json(items)
                }
            ).catch(
                (error)=>{
                    res.json({"status":"error"})
                }
            )
        } else {
            res.json({"status":"invalid authentication"})
        }
    })
})

app.post("/viewmypost",(req,res)=>{
    let input=req.body
    let token=req.headers.token
    Jwt.verify(token,"mytoken",(error,decoded)=>{
        if (decoded) {
            postModel.find(input).then(
                (items)=>{
                    res.json(items)
                }
            ).catch(
                (error)=>{
                    res.json({"status":error})
                }
            )
        } else {
            res.json({"status":"invalid authentication"})
        }
    })
})


app.post("/search",(req,res)=>{
    let input=req.body
    userModel.find(input).then(
        (data)=>{
            res.json(data)
        }
    ).catch(
        (error)=>{
            req.json(error)
        }
    )
})

app.post("/delete",(req,res)=>{
    let input=req.body
    userModel.findByIdAndDelete(input._id).then(
        (response)=>{
            res.json({"status":"success"})
        }
    ).catch(
        (error)=>{
            res.json({"status":"error"})
        }
    )
})

app.listen(8087,()=>{
    console.log("server started")
})