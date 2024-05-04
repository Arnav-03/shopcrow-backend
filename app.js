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

        jwt.sign(jwtPayload, jwtSecret, { expiresIn: '7d' }, (err, token) => {
            if (err) throw err;

            // Set cookie with appropriate attributes
            res.cookie('token', token, { sameSite: 'None', secure: true }).status(201).json({
                id: createdUser._id,
                username: createdUser.username,
                email: createdUser.email,
            });
        })
    } catch (err) {
        console.error(err);
        res.status(500).json({ error: 'Internal server error' });
    }
});

app.post('/api/cart', async (req, res) => {
    const { Cart } = req.body;

    try {
        // Extract user data from JWT token
        const token = req.cookies?.token;
        if (!token) {
            return res.status(401).json({ error: 'Unauthorized' });
        }

        const decoded = jwt.verify(token, jwtSecret);
        const { id, username, email, phonenumber } = decoded;

        // Prepare user data and cart info to be stored in cookies
        const userDataWithCart = {
            id,
            username,
            email,
            phonenumber,
            Cart
        };

        // Generate new JWT token with updated user data and cart info
        jwt.sign(userDataWithCart, jwtSecret, { expiresIn: '7d' }, (err, token) => {
            if (err) throw err;

            // Set cookie with updated JWT token
            res.cookie('token', token, { sameSite: 'None', secure: true }).status(200).json(userDataWithCart);
        });
    } catch (err) {
        console.error(err);
        res.status(500).json({ error: 'Internal server error' });
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
    const email = loginEmail;

    try {
        // Find user by email
        const foundUserEmail = await User.findOne({ email });

        // Check if user exists
        if (!foundUserEmail) {
            return res.status(401).json({ error: 'User not found' });
        }

        // Verify password
        const passOk = bcrypt.compareSync(loginPassword, foundUserEmail.password);
        if (!passOk) {
            return res.status(401).json({ error: 'Invalid password' });
        }

        // Generate JWT token
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

            // Set the JWT token cookie with appropriate attributes
            res.cookie('token', token, { sameSite: 'None', secure: true }).status(200).json({
                id: foundUserEmail._id,
                username: foundUserEmail.username,
                email: foundUserEmail.email,
                phonenumber: foundUserEmail.phonenumber,
            });
        }); 
    } catch (error) {
        console.error(error);
        res.status(500).json({ error: 'Internal server error' });
    }
});

app.post('/api/cartcookie', async (req, res) => {
    const { Cart } = req.body;

    try {
        // Extract user data from JWT token
        const token = req.cookies?.token;
        if (!token) {
            return res.status(401).json({ error: 'Unauthorized' });
        }

        const decoded = jwt.verify(token, jwtSecret);
        const { id, username, email, phonenumber } = decoded;

        // Prepare user data with cart info to be stored in cookies
        const userDataWithCart = {
            id,
            username,
            email,
            phonenumber,
            Cart
        };

        // Generate new JWT token with updated user data and cart info
        jwt.sign(userDataWithCart, jwtSecret, { }, (err, token) => {
            if (err) {
                console.error(err);
                return res.status(500).json({ error: 'Internal server error' });
            }
            res.cookie('token', token, { sameSite: 'None', secure: true }).status(201).json({
                id,
                username,
                email,
                phonenumber,
                Cart,
            });

        });
    } catch (err) {
        console.error(err);
        res.status(500).json({ error: 'Internal server error' });
    }
});

app.post('/api/deleteaccount/:id', async (req, res) => {
    const idToBeDeleted = req.params.id;

    try {
        // Find the user by ID
        const deletedUser = await User.findByIdAndDelete(idToBeDeleted);

        if (!deletedUser) {
            return res.status(404).json({ error: 'User not found' });
        }

        // Log out the user by clearing the token cookie
        res.cookie('token', '', { sameSite: 'none', secure: true }).json({ message: 'Account deleted successfully' });
    } catch (error) {
        console.error(error);
        res.status(500).json({ error: 'Internal server error' });
    }
});

app.post('/api/updateaccount/:field/:newvalue', async (req, res) => {
    const { field, newvalue } = req.params;
    
    try {
        // Extract user data from JWT token
        const token = req.cookies?.token;
        if (!token) {
            return res.status(401).json({ error: 'Unauthorized' });
        }

        const decoded = jwt.verify(token, jwtSecret);
        const { id } = decoded;

        // Update user field in the database
        await User.findByIdAndUpdate(id, { [field]: newvalue });

        // Fetch updated user data
        const updatedUser = await User.findById(id);

        // Generate new JWT token with updated user data
        const jwtPayload = {
            id: updatedUser._id,
            username: updatedUser.username,
            email: updatedUser.email,
            phonenumber: updatedUser.phonenumber,
        };

        jwt.sign(jwtPayload, jwtSecret, {}, (err, newToken) => {
            if (err) {
                console.error(err);
                return res.status(500).json({ error: 'Internal server error' });
            }

            // Set the JWT token cookie with appropriate attributes
            res.cookie('token', newToken, { sameSite: 'None', secure: true }).status(200).json({
                message: 'Field updated successfully',
                user: {
                    id: updatedUser._id,
                    username: updatedUser.username,
                    email: updatedUser.email,
                    phonenumber: updatedUser.phonenumber,
                }
            });
        });
    } catch (error) {
        res.status(500).json({ error: 'Internal server error' });
    }
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
        res.json(productDetails);
      } catch (error) {
        console.error("Error:", error);
        res.status(500).json({ message: "Internal server error" });
      }      
  });
  
export { app }