import express from 'express'
import mongoose from 'mongoose'
import 'dotenv/config'
import bcrypt from 'bcrypt'
import {nanoid} from 'nanoid'
import User from './Schema/User.js'
import cors from 'cors'
import jwt from 'jsonwebtoken'
import firebaseAdmin from 'firebase-admin'
import serviceAccountKey from './blogging-website-e6f4d-firebase-adminsdk-kxayr-72dfc53b8f.json' assert { type: "json" };
import {getAuth} from 'firebase-admin/auth'

import cloudinary from './configs/cloudinary.js'
import upload from './middleware/multer.js'
import Blog from './Schema/Blog.js'
import Notification from './Schema/Notification.js'

const server = express();
let PORT = 3000;

let emailRegex = /^\w+([\.-]?\w+)*@\w+([\.-]?\w+)*(\.\w{2,3})+$/; // regex for email
let passwordRegex = /^(?=.*\d)(?=.*[a-z])(?=.*[A-Z]).{6,20}$/; // regex for password

server.use(express.json())
server.use(cors());

mongoose.connect(process.env.DB_LOCATION, {
    autoIndex: true
})

firebaseAdmin.initializeApp({
    credential: firebaseAdmin.credential.cert(serviceAccountKey)
});


const formDataToSend = (user) => {
    const access_token = jwt.sign({id: user._id}, process.env.SECRET_ACCESS_KEY)
    return{
        access_token,
        profile_img: user.personal_info.profile_img,
        username: user.personal_info.username,
        username: user.personal_info.fullname
    }
}

const generalUsername = async(email) => {
    
    let userName = email.split('@')[0];

    let isUserNameNotUnique = await User.exists({'personal_info.username': userName}).then((result) => result)

    isUserNameNotUnique ? userName += nanoid().substring(0, 5) : '';

    return userName
}

const verifyJWT = (req, res, next) => {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(" ")[1];

    if(token == null) return res.status(401).json({error: 'No access token'})

    jwt.verify(token, process.env.SECRET_ACCESS_KEY, (err, user) => {
        if(err) return res.status(403).json({error: 'Access token is invalid'})

        req.user = user.id

        next()
    })
}


server.post('/signup', (req, res) => {
    let { fullname, email, password } = req.body;

    //validate data 
    if (fullname.length < 3) {
        return res.status(403).json({ 'error': 'fullname must be at least 3 letters long' })
    }
    if (!email.length) {
        return res.status(403).json({ 'error': 'Enter Email' })
    }
    if (!emailRegex.test(email)) {
        return res.status(403).json({ 'error': 'Email invalid' })
    }
    if (!passwordRegex.test(password)) {
        return res.status(403).json({ 'error': 'Password should be 6 to 28 characters long with a numeric, lowercase and 1 upercase letters ' })
    }
    bcrypt.hash(password, 10, async (err, hashed_password) => {
        let username = await generalUsername(email);

        let user = new User({
            'personal_info':{fullname, email, password: hashed_password, username}
        })
        user.save().then((u) => {
            return res.status(200).json(formDataToSend(u))
        })
        .catch(err => {
            if(err.code == 11000){
                return res.status(500).json({'error': 'Email already exists'})
            }
            return res.status(500).json({'error': err.message})
        })

    });

})

server.post('/signin', (req, res) => {
    let {email, password} = req.body
    User.findOne({'personal_info.email': email})
    .then((user) => {
        if(!user){
            return res.status(403).json({'error': 'Email not found'});
        }

        bcrypt.compare(password, user.personal_info.password , (err, result) => {
            if(err) return res.status(403).json({'error': 'Error occured while login please try again'});
            
            if(!result){
                return res.status(403).json({'error': 'Incorrect password'});
            }else{
                return res.status(200).json(formDataToSend(user))
            }


        })
    })
    .catch(err => {
        return res.status(500).json({'error': err.message});
    })
})

server.post('/google-auth', (req, res) => {
    let {access_token} = req.body;

    getAuth()
    .verifyIdToken(access_token)
    .then(async (decodeUser) => {
        let { email, name, picture } = decodeUser;

        picture = picture.replace('s96-c' , 's384-c')

        let user = await User.findOne({'personal_info.email': email}).select('personal_info.fullname personal_info.username personal_info.profile_img google_auth')
        .then((u) => u || null)
        .catch((error) => res.status(500).json({'error': error.message}))

        if(user){

            if(!user.google_auth) return res.status(405).json({'error': 'This email was signed up without google. Please login with password to access the account'})

        }
        else {
            let username = await generalUsername(email);

            user = new User({
                personal_info: {fullname: name, email, profile_img: picture, username},
                google_auth: true
            })

            await user.save().then((u) => {
                user = u
            })
            .catch(err => res.status(500).json({'error': err.message}))
        }

        return res.status(200).json(formDataToSend(user))
    })
    .catch(err => res.status(500).json({'error': 'Failed to authencation you to with google. Try with some google other account'}))

})

server.post('/upload-image', upload.single('image'), (req, res) => {
    cloudinary.uploader.upload(req.file.path, (err, result) => {
        if(err) {
            console.log(err);
            return res.status(500).json({
              success: false,
              message: "Error"
            })
          }
      
          res.status(200).json({
            success: true,
            message:"Uploaded!",
            data: result
          })
    })
})

server.post('/latest-blogs', (req, res) => {

    let {page} = req.body

    let maxLimit = 5
    Blog.find({draft: false})
    .populate("author", "personal_info.profile_img personal_info.username personal_info.fullname -_id")
    .sort({'publishedAt': -1})
    .select("blog_id title des banner activity tags publishedAt -_id")
    .skip((page - 1) * maxLimit)
    .limit(maxLimit)
    .then(blogs => res.status(200).json({blogs}))
    .catch(err => res.status(500).json({error: err.message}))

})

server.post('/all-latest-blogs-count', (req, res) => {
    Blog.countDocuments({draft: false})
    .then(count => res.status(200).json({totalDocs: count}))
    .catch(err => res.status(500).json({error: err.message}))
})

server.get('/trending-blogs', (req, res) => {
    Blog.find({draft: false})
    .populate("author", "personal_info.profile_img personal_info.username personal_info.fullname -_id")
    .sort({"activity.total_reads": -1, "activity.total_likes": -1, "publishAt":-1})
    .select("blog_id title publishedAt -_id")
    .limit(5)
    .then(blogs => res.status(200).json({blogs}))
    .catch(err => res.status(500).json({ error:err.message }))
})

server.post('/search-blogs', (req, res) => {
    let {tag,query, author, page, limit, eliminate_blog} = req.body

    let findQuery 

    if(tag){
        findQuery = {tags: tag, draft: false, blog_id: {$ne: eliminate_blog}}
    }else if(query){
        findQuery = {title: new RegExp(query, 'i'), draft: false}
    }else if(author){
        findQuery = {author, draft: false,}
    }
    let maxLimit = limit ? limit : 2;

    Blog.find(findQuery)
    .populate("author", "personal_info.profile_img personal_info.username personal_info.fullname -_id")
    .sort({'publishedAt': -1})
    .select("blog_id title des banner activity tags publishedAt -_id")
    .skip((page - 1) * maxLimit)
    .limit(maxLimit)
    .then(blogs => res.status(200).json({blogs}))
    .catch(err => res.status(500).json({error: err.message}))
})

server.post('/search-blogs-count', (req, res) => {
    let {tag, author, query} = req.body;

    let findQuery

    if(tag){
        findQuery = {tags: tag, draft: false}
    }else if(query){
        findQuery = {title: new RegExp(query, 'i'), draft: false}
    }else if(author){
        findQuery = {author, draft: false,}
    }

    Blog.countDocuments(findQuery)
    .then(count => res.status(200).json({totalDocs: count}))
    .catch(err => res.status(500).json({error: err.message}))
})

server.post('/search-users', (req, res) => {
    let {query} = req.body
    
    User.find({"personal_info.username": new RegExp(query, 'i')})
    .limit(50)
    .select("personal_info.fullname personal_info.username personal_info.profile_img -_id")
    .then(users => res.status(200).json({users}))
    .catch(err => res.status(500).json({error: err.message}))
    
})

server.post('/get-profile', (req, res) => {
    let {username} = req.body

    User.findOne({"personal_info.username": username})
    .select("-personal_info.password -google_auth -updatedAt -blogs")
    .then(user => res.status(200).json(user))
    .catch(err => res.status(500).json({error: err.message}))

})

server.post('/create-blog', verifyJWT, (req, res) => {
    let authorId = req.user

    let {title, des, banner, tags, content, draft, id} = req.body

    if(!title.length) return res.status(403).json({error: 'You must provide a title'});

    if(!draft){
        if(!des. length) return res.status(403).json({error: 'You must provide blog description under 200 characters'});
    
        if(!banner.length) return res.status(403).json({error: 'you must provide blog banner to publish it'});
        
        if(!content.blocks.length) res.status(403).json({error: 'There must be some blog content to publish it'});
    
        if(!tags.length || tags.length > 10) res.status(403).json({error: 'Provide tags in order to publish the blog, Maximum 10'});
    }

    tags = tags.map(tag => tag.toLowerCase());

    let blog_id = id || title.replace(/[^a-zA-Z0-9]/g, '').replace(/\s+/g, "-").trim() + nanoid();

    if(id){
        Blog.findOneAndUpdate({blog_id}, {title, des, banner, content, tags, draft: draft ? draft : false})
        .then(() => res.status(200).json({id: blog_id}))
        .catch(err => res.status(500).json({error: 'Failed to update total post number'}))
        
    }else{
        let blog = new Blog({
            title, des, banner, content, tags, author: authorId, blog_id, draft: Boolean(draft)
        })
    
        blog.save().then(blog => {
            let incrementVal = draft ? 0 : 1;
    
            User.findOneAndUpdate({_id: authorId}, {$inc: {'account_info.total_posts': incrementVal}, $push : {"blogs": blog._id}})
            .then(user => {
                return res.status(200).json({id: blog.blogId})
            })
            .catch(error => {
                return res.status(500).json({error: "Failed to update total posts number"})
            })
        })
        .catch(err => {
            return res.status(500).json({error: err.message})
        })
        return res.json({status: 'done'})
    }



})

server.post('/get-blog', (req, res) => {
    let { blog_id, draft, mode } = req.body

    let incrementVal = mode !== 'edit' ? 1 : 0;

    Blog.findOneAndUpdate({ blog_id }, {$inc : {"activity.total_reads": incrementVal}})
    .populate("author", "personal_info.fullname personal_info.username personal_info.profile_img")
    .select("title des content banner activity publishedAt blog_id tags")
    .then(blog => {
        User.findOneAndUpdate({"personal_info.username": blog.author.personal_info.username}, {$inc: {"account_info.total_reads": incrementVal}})
        .catch(err => res.status(500).json({ error: err.message}))

        if(blog.draft && !draft){
            return res.status(500).json({error: 'you can not access draft blogs'})
        }
        return res.status(200).json({blog})
    } )
    .catch(err => res.status(500).json({error: err.message})) 
})

server.post('/like-blog', verifyJWT, (req, res) => {
    let user_id = req.user

    let {_id, isLikeByUser} = req.body

    let incrementVal = !isLikeByUser ? 1 : -1

    Blog.findOneAndUpdate({_id}, {$inc: {"activity.total_likes": incrementVal}})
    .then(blog => {
        if(!isLikeByUser){

            let like = new Notification({
                type: 'like',
                blog: _id,
                notification_for: blog.author,
                user: user_id
            })

            like.save().then(notification => res.status(200).json({liked_by_user: true}))

        }else{
            Notification.findOneAndDelete({user: user_id, blog: _id, type: 'like'})
            .then(data => res.status(200).json({liked_by_user: false}))
            .catch(err => res.status(500).json({error: err.message}))
        }
    })
})

server.post('/isLiked-by-user', verifyJWT, (req, res) => {
    let user_id = req.user
    
    let {_id} = req.body

    Notification.exists({user: user_id, type: 'like', blog: _id})
    .then(result => res.status(200).json({result}))
    .catch(err => res.status(500).json({error: err.message}))
})

server.listen(PORT, () => {
    console.log('listening port', PORT);
})
