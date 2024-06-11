import express from "express"
import cors from "cors"
import cookieParser from "cookie-parser"
import dotenv from 'dotenv'
import bcrypt from 'bcryptjs'
import mongoose from "mongoose"
import jwt from "jsonwebtoken"
import { User } from './models/user.model.js'
import Order from './models/order.model.js'
import Product from './models/product.model.js'
import Stripe from 'stripe';
import { v4 as uuidv4 } from 'uuid';

const stripe = new Stripe('sk_test_51PCgLhSFcgaeLbhlRY6BqaoON8LQ9nRIi7awdocQ9oOej37qLnY3YtYNaiU8xuoB9ojri1jYIUsihibtlFjX0AnP00wFwwwZ8S');


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
app.post('/api/searchresults/:search', async (req, res) => {
    const search = req.params.search;
    try {
        const results = await Product.find({
            $or: [
                { category: { $regex: search, $options: 'i' } },
                { subcategory: { $regex: search, $options: 'i' } },
                { tagline: { $regex: search, $options: 'i' } }

            ]
        });

        res.json(results);


    } catch (error) {

    }
})
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
        jwt.sign(userDataWithCart, jwtSecret, {}, (err, token) => {
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
        const latestProducts = await Product.find({ category: categorytype }).sort({ createdAt: -1 }).limit(5); // Fetch top 5 latest products in the specified category
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


app.post('/api/payment', async (req, res) => {
    const { product, token } = req.body;
    console.log(product);

    const idempontencyKey = uuidv4();

    return stripe.customers.create({
        email: token.email,
        source: token.id
    }).then(customer => {
        stripe.charges.create({
            customer: customer.id,
            amount: product.price * 100,
            currency: 'inr',
            receipt_email: token.email,
            description: product.description,
            shipping: {
                name: token.card.name,
                address: {
                    country: token.card.address_country
                }
            }
        }, { idempontencyKey })
    }).then(result => { res.status(200).json(result) })
        .catch(error => console.error(error));
})

app.post("/webhook", async (req, res) => {
    let event;

    try {
        // Verify the webhook signature
        event = stripe.webhooks.constructEvent(
            req.rawBody,
            req.headers['stripe-signature'],
            process.env.STRIPE_WEBHOOK_SECRET
        );
    } catch (err) {
        console.error("Webhook error:", err.message);
        return res.status(400).send(`Webhook Error: ${err.message}`);
    }

    // Handle the event
    if (event.type === 'checkout.session.completed') {
        const session = event.data.object;
        const paymentId = session.payment_intent; // Payment ID
        console.log('Payment ID:', paymentId);
        // Now you can use the payment ID as needed
    }

    res.status(200).json({ received: true });
});

const stripeWebhookHandler = async (req, res) => {
    let event;
  
    try {
        const sig = req.headers["stripe-signature"];
        event = stripe.webhooks.constructEvent(
            req.body,
            sig,
            process.env.STRIPE_KEY // Assuming you have configured your Stripe endpoint secret in environment variables
        );
    } catch (error) {
        console.log(error);
        return res.status(400).send(`Webhook error: ${error.message}`);
    }
  
    if (event.type === "checkout.session.completed") {
        const session = event.data.object;
      
        // Retrieve the order ID from the metadata
        const orderId = session.metadata?.orderId;
  
        if (!orderId) {
            return res.status(400).send("Order ID not found in session metadata");
        }
  
        const order = await Order.findById(orderId);
  
        if (!order) {
            return res.status(404).json({ message: "Order not found" });
        }
  
        order.totalAmount = session.amount_total;
        order.status = "paid";
  
        await order.save();
    }
  
    res.status(200).send();
};

// Mount the webhook handler as a route
app.post("/stripe-webhook", express.raw({ type: 'application/json' }), stripeWebhookHandler);

// Define the create checkout session endpoint
app.post("/api/create-checkout-session", async (req, res) => {
    try {
        const { userId, items, amount, address } = req.body;

        if (!userId || !items || !amount ) {
            return res.status(400).json({ error: 'Missing required fields' });
        }

        // Generate a unique payment ID
        const paymentId = uuidv4();
        console.log(paymentId);

        // Create Stripe checkout session
        const session = await stripe.checkout.sessions.create({
            payment_method_types: ["card"],
            line_items: items.map(({ id, quantity, name, priceInCents }) => ({
                price_data: {
                    currency: "inr",
                    product_data: {
                        name: name,
                    },
                    unit_amount: priceInCents,
                },
                quantity: quantity,
            })),
            mode: "payment",
            success_url: `${process.env.CORS_ORIGIN}/OrderStatus/${paymentId}`,
            cancel_url: `${process.env.CORS_ORIGIN}/cancel`,
            metadata: {
                orderId: paymentId // Store the order ID in metadata
            }
        });

        const paymentIntentId = session.payment_intent; // Get payment intent ID
        console.log(paymentIntentId);

        // Create a new order in the database
        const newOrder = new Order({
            paymentId: paymentId, // Use the generated payment ID as the order ID
            userId: userId,
            items: items,
            amount: amount,
            address: address,
            status: "processing",
            payment: false,
        });

        await newOrder.save();

        res.json({ url: session.url, paymentId: paymentId, transactionId: paymentIntentId });
    } catch (e) {
        res.status(500).json({ error: e.message });
    }
});


app.post('/api/order', async (req, res) => {
    try {
        const { useridd, username, email, items, amount, address } = req.body;
        const token = req.cookies?.token;
        if (!token) {
            return res.status(401).json({ error: 'Unauthorized' });
        }

        const decoded = jwt.verify(token, jwtSecret);
        const { id } = decoded;
        const userId = id;
        const newOrder = await Order.create({
            userId,
            useridd,
            username,
            email,
            items,
            amount,
            address,
        });
        res.status(201).json(newOrder);
    } catch (error) {
        console.error('Error creating order:', error);
        res.status(500).json({ error: 'Internal server error' });
    }
});

app.post('/api/checktransaction/:paymentId', async (req, res) => {
    try {
        const paymentId = req.params.paymentId; // Corrected
        const OrderDetails = await Order.find({ paymentId: paymentId });
        res.json(OrderDetails);
    } catch (error) {
        console.error("Error:", error);
        res.status(500).json({ message: "Internal server error" });
    }
});

app.get('/api/orders/:paymentId', async (req, res) => {
    const { paymentId } = req.params;
  
    try {
      const order = await Order.findOne({ paymentId });
      if (!order) {
        return res.status(404).json({ message: 'Order not found' });
      }
      res.json(order);
    } catch (error) {
      console.error('Error fetching order:', error);
      res.status(500).json({ message: 'Server error' });
    }
  });

  app.put('/api/paymentupdate/:paymentId', async (req, res) => {
    const { paymentId } = req.params;
  
    try {
      const updatedOrder = await Order.findOneAndUpdate(
        { paymentId },
        { $set: { payment: true, status: 'completed' } }, // Set the 'payment' field to true and 'status' to 'completed'
        { new: true }
      );
  
      if (!updatedOrder) {
        return res.status(404).json({ message: 'Order not found' });
      }
  
      res.json(updatedOrder);
    } catch (error) {
      console.error('Error updating payment status:', error);
      res.status(500).json({ message: 'Server error' });
    }
  });

  
  app.post('/api/userorderhistory', async (req, res) => {
    const { userId } = req.body;
    try {
      const orders = await Order.find({ userId:userId });
      res.json(orders);
      console.log(orders)

    } catch (error) {
      res.status(500).json({ message: 'Error fetching user orders', error });
    }
  });
export { app }