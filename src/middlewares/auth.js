const jwt = require('jsonwebtoken')
const blogModel = require('../Models/BlogModel')
const accessKey = "someverysecuredprivatekey"
const authorAuth = async (req, res, next) => {
  try {
    const token = req.header('x-api-key')
    if (!token) {
      res.status(403).send({ status: false, message: `Missing authentication token in request` })
      return;
    }
    const decoded = await jwt.verify(token, accessKey)
    if (!decoded) {
      res.status(403).send({ status: false, message: `Invalid authentication token in request` })
      return;
    }
    req.authorId = decoded.authorId;
    next()
  } catch (error) {
    console.error(`Error! ${error.message}`)
    res.status(500).send({ status: false, message: error.message })
  }
}
// const jwtauth2 = async function (req, res, next) {
//   try {
//     //authenticate
//     let token = req.headers["x-api-key"];
//     if (!token) return res.status(401).send({ status: false, msg: "token must be present" });
//     let decodedToken = jwt.verify(token, accessKey
//       );
//     if (!decodedToken)
//       return res.status(401).send({ status: false, msg: "token is invalid" });
//     let blogId = req.params.blogId   
//     if (!blogId) res.status(400).send({ status: false, msg: "blogid is not present" })
//     let tsobject = await blogModel.findById(blogId);
//     if (!tsobject) { return res.status(404).send({ status: false, msg: "data is not Found" }) }
//     let authorId = tsobject.authorId
//     let authorLoggedIn = decodedToken.authorId
//     if (authorId != authorLoggedIn) return res.status(401).send({ status: false, msg: 'Author logged is not allowed to modify the requested authors data' })
//     next()
//   } catch (error) {
//     return res.status(500).send(error.message)
//   }
// }

module.exports.authorAuth = authorAuth
// module.exports.jwtauth2 = jwtauth2