import express from "express"
import cors from "cors"
import cookieParser from "cookie-parser"
import dotenv from 'dotenv'
import bcrypt from 'bcryptjs'
import mongoose from "mongoose"
import jwt from "jsonwebtoken"
import { User } from './models/user.model.js'
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



app.get('/', async (req, res) => {
    const options = {
        method: 'GET',
        url: 'https://amazon-scraper21.p.rapidapi.com/products/B07K2PK3BV',
        params: {
          api_key: 'jhrv34yrtg479g4uyfb4fyhb43yhtb74'
        },
        headers: {
          'X-RapidAPI-Key': 'ba70b0675fmshbbc06c5afed7339p1329f2jsn38851fa7386b',
          'X-RapidAPI-Host': 'amazon-scraper21.p.rapidapi.com'
        }
      };
      
      try {
          const response = await axios.request(options);
          res.send(response.data);
      } catch (error) {
          console.error(error);
      }
    /*  try {
        // Fetch data from the external API
        const response = await fetch('https://dummyjson.com/products/categories');
        if (!response.ok) {
            throw new Error('Failed to fetch products');
        }
        const json = await response.json();
        
        // Send the JSON data as a response
        res.json(json);
    } catch (error) {
        console.error('Error fetching products:', error);
        res.status(500).json({ error: 'Internal server error' });
    }  */
});

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

export { app }