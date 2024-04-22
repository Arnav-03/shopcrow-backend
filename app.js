import express from "express"
import cors from "cors"
import cookieParser from "cookie-parser"
import dotenv from 'dotenv'
import bcrypt from 'bcryptjs'
import mongoose from "mongoose"
import jwt from "jsonwebtoken"
import { User } from './models/user.model.js'
import Product from './models/product.model.js'
dotenv.config();

import axios from 'axios';
const jwtSecret = process.env.JWT_SECRET;
const bcryptSalt = bcrypt.genSaltSync(10);


const app = express()

app.use(cors({
    origin: process.env.CORS_ORIGIN,
    credentials: true
}))


app.use(express.json({ limit: "16kb" }))
app.use(express.urlencoded({ extended: true, limit: "16kb" }))
app.use(express.static("public"))
app.use(cookieParser())





//take user input while register
app.post('/api/register', async (req, res) => {
    const { username, email, password, phoneno } = req.body;
    console.log("recieving data -> ", username, email, password, phoneno);

    try {
        const hashedPassword = bcrypt.hashSync(password, bcryptSalt);
        const createdUser = await User.create({
            username: username,
            password: hashedPassword,
            email: email,
            phonenumber: phoneno,
        });
        // Generate JWT token
        const jwtPayload = {
            id: createdUser._id,
            username: createdUser.username,
            email: createdUser.email,
            phonenumber: createdUser.phonenumber,
        };

 jwt.sign(jwtPayload, jwtSecret, {}, (err, token) => {
            if (err) throw err;
         

            res.cookie('token', token, { sameSite: 'none', secure: true }).status(201).json({
                id: createdUser._id,
                username: createdUser.username,
                email: createdUser.email,
            });
        })
    } catch (err) {
        if (err) throw err;
    }

});


app.get('/api/profile', (req, res) => {
    const token = req.cookies?.token;
    if (token) {
        jwt.verify(token, jwtSecret, {}, (err, userData) => {
            if (err) throw err;
            res.json(userData);
        });
    } else {
        res.status(401).json('no token');
    }
});
app.post('/api/login', async (req, res) => {
    const { loginEmail, loginPassword } = req.body;
    console.log(loginEmail, loginPassword);
    const email = loginEmail;
    const foundUserEmail = await User.findOne({ email });

    if (!foundUserEmail) {
        return res.status(401).json({ error: 'User not found' });
    }

    const passOk = bcrypt.compareSync(loginPassword, foundUserEmail.password);

    if (!passOk) {
        return res.status(401).json({ error: 'Invalid password' });
    }

    const jwtPayload = {
        id: foundUserEmail._id,
        username: foundUserEmail.username,
        email: foundUserEmail.email,
        phonenumber: foundUserEmail.phonenumber,
    };

   jwt.sign(jwtPayload, jwtSecret, {}, (err, token) => {
        if (err) {
            console.error(err);
            return res.status(500).json({ error: 'Internal server error' });
        }

        res.cookie('token', token, { httpOnly: true }).status(200).json({
            id: foundUserEmail._id,
            username: foundUserEmail.username,
            email: foundUserEmail.email,
            phonenumber: foundUserEmail.phonenumber,
        });
    }); 

   /*  res.json({
        user: {
            id: foundUserEmail._id,
            username: foundUserEmail.username,
            email: foundUserEmail.email,
            phonenumber: foundUserEmail.phonenumber,
        }
    }); */
});


app.post('/api/logout', (req, res) => {

    res.cookie('token', '', { sameSite: 'none', secure: true }).json('logout');
});

app.post('/api/product', async (req, res) => {
    try {
        const { id, image, name, category, subcategory, tagline, quantity, price } = req.body;

        // Create a new product
        const createdProduct = await Product.create({
            id,
            image,
            name,
            category,
            subcategory,
            tagline,
            quantity,
            price
        });

        console.log("Received data ->", createdProduct);

        // Send response
        res.status(201).json(createdProduct);
        
    } catch (error) {
        console.error("Error:", error);
        res.status(500).json({ error: 'Internal Server Error' });
    }
});


// Assuming you have a Product model defined and imported from your database configuration file

app.get('/api/products/latest/:category', async (req, res) => {
    try {
      const categorytype = req.params.category;
      const latestProducts = await Product.find({ category:categorytype }).sort({ createdAt: -1 }).limit(5); // Fetch top 5 latest products in the specified category
      res.json(latestProducts);
    } catch (error) {
      console.error("Error:", error);
      res.status(500).json({ message: "Internal server error" });
    }
  });
  app.get('/api/products/trending/:category', async (req, res) => {
    try {
        const categoryType = req.params.category;
        const latestProducts = await Product.find({ category: categoryType }).sort({ createdAt: 1 }).limit(5); // Fetch top 5 latest products in the specified category, sorted in reverse order
        res.json(latestProducts);
      } catch (error) {
        console.error("Error:", error);
        res.status(500).json({ message: "Internal server error" });
      }      
  });
  app.get('/api/product/:id', async (req, res) => {
    try {
        const id = req.params.id;
        const productDetails = await Product.find({ _id: id }); 
        console.log(productDetails);
        res.json(productDetails);
      } catch (error) {
        console.error("Error:", error);
        res.status(500).json({ message: "Internal server error" });
      }      
  });
  
export { app }