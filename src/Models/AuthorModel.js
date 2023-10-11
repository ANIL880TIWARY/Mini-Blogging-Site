const mongoose = require('mongoose');

const AuthorSchema = new mongoose.Schema({
  firstname:{
      type:String,
      required: true
  },
  lastname: {
      type :String,
      required:true
  },
  title: {
      type:String,
      required:true,
      enum:["Mr", "Mrs", "Miss"]
  },
  email: { type: String, trim: true, lowercase: true, unique: true, required: 'Email address is required',
  validate: {
      validator: function (email) {
          return /^\w+([\.-]?\w+)*@\w+([\.-]?\w+)*(\.\w{2,3})+$/.test(email)
      }, message: 'Please fill a valid email address', isAsync: false
  }
},
 password:{
     type:String,
     required:true,
     trim:true
    }
    },{timestamps:true})


 module.exports = mongoose.model('authors', AuthorSchema)