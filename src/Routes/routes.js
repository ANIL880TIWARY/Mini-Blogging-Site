const express = require('express');
const router = express.Router();

const AuthorController = require("../controllers/authorController")
const BlogController = require("../controllers/blogController")
const authorAuth = require("../middlewares/auth")



router.post("/CreateUser", AuthorController.createAuthor )


router.post('/resetPassword/:id/:token',AuthorController.resetPassword)

router.post("/CreateBlog", authorAuth.authorAuth,BlogController.createBlog )

router.get("/getAuthorsData",authorAuth.authorAuth,BlogController.getlistBlog)

router.put("/blogs/:blogId",authorAuth.authorAuth, BlogController.updateBlog)

router.delete("/blogs/:blogId",authorAuth.authorAuth, BlogController.deleteBlogByID)

router.delete("/blogs",authorAuth.authorAuth, BlogController.deleteBlogByParams)

router.post('/login', AuthorController.loginAuthor);

router.post('/getLink', AuthorController.sendMail);

module.exports = router;





















