const mongoose = require ("mongoose");
const schema = mongoose.Schema; //exports a class called Schema
const ObjectId = mongoose.ObjectId;

const User = new schema({
    email : {type:String,unique : true},    
    password : String ,
    name : String
})

const Todo = new schema({
    title: String ,
    done: Boolean ,
    userId : ObjectId 
})

const UserModel = mongoose.model("users",User);
const TodoModel = mongoose.model("todos",Todo);

// .model let's us create the collection called "users" with the schema User

module.exports={
    UserModel : UserModel ,
    TodoModel : TodoModel
}