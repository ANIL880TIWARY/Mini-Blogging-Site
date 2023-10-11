const AuthorModel = require("../Models/AuthorModel")
const bcrypt = require("bcrypt")
const jwt = require('jsonwebtoken')
const accessKey = "someverysecuredprivatekey"

//------------- ISVALID FUNCTION
const isValid = function (value) {
    if (typeof value === 'undefined' || value === null) return false
    if (typeof value === 'string' && value.trim().length === 0) return false
    return true;
}
//---------------------ISVALIDREQUESTBODY FUNCTION
const isValidRequestBody = function (requestBody) {
    return Object.keys(requestBody).length > 0
}
//------------------ISVALIDOBJECTID FUNCTION
const isValidObjectId = function (objectId) {
    return mongoose.Types.ObjectId.isValid(objectId)
}


const createAuthor = async function (req, res) {
    try {
        const requestBody = req.body;
        if (!isValidRequestBody(requestBody)) {
            res.status(400).send({ status: false, message: 'Please provide details for create auothor' })
            return

        }
        const { firstname, lastname, title, email, password } = requestBody
        if (!isValid(firstname)) {
            res.status(400).send({ status: false, message: 'Please provide First Name' })
            return
        }
        if (!isValid(lastname)) {
            res.status(400).send({ status: false, message: 'Please provide Last Name' })
            return
        }
        if (!isValid(title)) {
            res.status(400).send({ status: false, message: 'Please provide Title' })
            return
        }
        if (!isValid(email)) {
            res.status(400).send({ status: false, message: 'Please provide Email-id' })
            return
        }
        const isemail = await AuthorModel.findOne({ email })
        if (isemail) {
            res.status(400).send({ status: false, message: 'email already used' })
            return
        }
        if (!isValid(password)) {
            res.status(400).send({ status: false, message: 'Please provide Password' })
            return
        }
        const hashPass = await bcrypt.hash(password, 10)

        const author = { firstname, lastname, title, email, password: hashPass }
        let authorCreated = await AuthorModel.create(author)
        res.status(201).send({ data: authorCreated, msg: "Author created successfully" })
    }
    catch (error) {
        console.log(error)
        res.status(500).send(error.message)
    }
}

const loginAuthor = async function (req, res) {
    try {
        const requestBody = req.body;
        if (!isValidRequestBody(requestBody)) {
            res.status(400).send({ status: false, message: 'Invalid request parameters. Please provide login details' })
            return
        }
        // EXTRACT PARAMS
        const email = requestBody.email
        const password = requestBody.password
        // VALIDATION STARTS
        if (!isValid(email)) {
            res.status(400).send({ status: false, message: `Email is required` })
            return
        }
        if (!(/^\w+([\.-]?\w+)*@\w+([\.-]?\w+)*(\.\w{2,3})+$/.test(email.trim()))) {
            res.status(400).send({ status: false, message: `Email should be a valid email address` })
            return
        }
        if (!isValid(password.trim())) {
            res.status(400).send({ status: false, message: `Password is required` })
            return
        }
        // FIND AUTHOR DETAIL
        const authEmail = await AuthorModel.find({ email: email })
        if (!authEmail) {
            res.status(401).send({ status: false, message: `Invalid Email` });
            return
        }
        // console.log(authEmail[0].password)
        const isAuth = await bcrypt.compare(password.trim(), authEmail[0].password)
        if (!isAuth) {
            res.status(401).send({ status: false, message: `Invalid Password` });
            return
        }

        // GENERATE JWT TOKEN
        const token = await jwt.sign({
            authorId: authEmail._id
        }, accessKey)
        res.header('x-api-key', token);
        res.status(200).send({ status: true, message: `Author login successfull`, data: token });
    } catch (error) {
        res.status(500).send({ status: false, message: error.message });
    }
}

const sendMail = async function (req, res) {
    try {
        const data = req.body
        if (!isValidRequestBody(data)) {
            res.status(400).send({ status: false, message: 'Invalid request parameters. Please provide details' })
            return
        }
        const email = data.email
        if (!email.trim()) {
            res.status(400).send({ status: false, message: 'Pleale Provide Email' })
            return
        }
        const isEmail = await AuthorModel.findOne({ email: email })
        if (!isEmail) {
            res.status(400).send({ status: false, message: 'Invalid Email' })
            return
        }
        const secret = isEmail._id.toString() + accessKey
        //    console.log(secret)

        const token = jwt.sign({ tokenId: isEmail._id.toString() }, secret, { expiresIn: '15m' })
        const link = `localhost:3000/resetPassword/${isEmail._id.toString()}/${token}`
        //   const link = `http://127.0.0.1:5000/reset/${isEmail._id.toString()}/${token}`
        // console.log(link)
        res.status(200).send({ status: true, data: `Change Password Link   ${link} ` })
    }
    catch (err) {

        res.status(500).send(err)
    }

}

const resetPassword = async function (req, res) {

    const { id, token } = req.params
    const { password, Confirm_Password } = req.body
    const isUser = await AuthorModel.findById(id)
    if (!isUser) {
        res.status(400).send({ status: false, message: 'Link Not Valid' })
        return
    }
    try {
        const newSecret = isUser._id.toString() + accessKey
        const vartoken = await jwt.verify(token, newSecret)
        if (!vartoken) {
            res.status(400).send({ status: false, message: 'Please input Valid Link' })
            return
        }
        if (!password.trim() && !Confirm_Password.trim()) {
            res.status(400).send({ status: false, message: 'Please Fill Data' })
            return
        }
        if (password === Confirm_Password) {
            const hashPassword = await bcrypt.hash(password, 10)
            // await model.findByIdAndUpdate(isUser._id.toString(), { password: hashPassword })
            await AuthorModel.findByIdAndUpdate(isUser._id.toString(), { $set: { password: hashPassword } })
            res.status(200).send({ status: true, message: 'Password Changed successfully' })
        } else {
            res.status(400).send({ status: false, message: 'Password & Confirm_Password not match' })
            return
        }
    }
    catch (err) {
        res.status(500).send({ status: false, message: err.message })
    }
}




module.exports = { createAuthor, loginAuthor, sendMail, resetPassword }


