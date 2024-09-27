const bcrypt = require("bcrypt")
const express = require("express");
const app = express();
const jwt = require("jsonwebtoken");
const JWT_SECRET = "asad@ssd";
const { z } = require("zod");

const { UserModel , TodoModel } = require("./db");
const { default: mongoose } = require("mongoose");
mongoose.connect(" ");

app.use(express.json()); //since we're parsing the json body possible only using the express.json()

app.post("/signup",async (req,res)=>{
    const email = req.body.email ;
    const name = req.body.name ; 
    const password = req.body.password ; 

    const requirebody = z.object({
        email:z.string().min(3).max(100).email(),
        name:z.string().min(3).max(100),
        password:z.string().min(3).max(100)
    })
    const parsedDataWithSuccess = requirebody.safeParse(req.body);
    //1.show the warning msg to user 
    if(!parsedDataWithSuccess.success){
        res.json({
            message:"incorrect format",
            error:parsedDataWithSuccess
        })
        return 
    }
    try {
    const hashedPassword = await bcrypt.hash(password,5);//here 5 is saltrounds i.e no.of iterations it needs to be hashed
    console.log(hashedPassword);
    
    await UserModel.create({
        email:email , 
        name:name , 
        password:hashedPassword ,
    })}

    catch(e){
        res.json({
            message:"User already exists ",
        })        
    }

    res.json({
        message:"You are logged in "
    })
});

app.post("/signin",async function (req,res) {
    const email = req.body.email ; 
    const password = req.body.password ; 

    const user = await UserModel.findOne({
        email : email , 
         
    })
    if(!user){
        res.status(404).json({
           message:"User doesn't exist in our db" 
        })
        return
    }
    const passwordMatch = await bcrypt.compare(password,user.password);
    //chk if the user is present 
    if(passwordMatch){
        const token  = jwt.sign({
            id : user._id.toString()
        },JWT_SECRET);

        res.json({
            token:token
        });
    }else{
        res.status(404).json({
            message:"Incorrect credentials"
        })
    }
    
})


app.post("/todo",auth,async (req,res)=>{
    const userId = req.body.userId ;
    const title = req.body.title;
    const done = req.body.done ;
    await TodoModel.create({
        title,
        userId,
        done
    })
    res.json({
        message:"Todo created"
    })
})

app.get("/todos",auth,async(req,res)=>{
    const userId = req.userId ; 
    const todos = await TodoModel.find({    //todos return krdia
        userId : userId 
    })
    res.json({
        todos
    })   
})

function auth(req,res,next){
    const token = req.headers.token ;
    const decodedData = jwt.verify(token , JWT_SECRET);

    if(decodedData){
        req.userId = decodedData.Id ; 
        next();
    }
    else{
        res.status(403).json({
            message:"Incorrect Credentials"
        })
    }

}

app.listen(3000);
