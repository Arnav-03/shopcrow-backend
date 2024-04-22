import mongoose, { Schema } from "mongoose";

const productSchema = new Schema(
    {
        id: {
            type: String,
            required: true
        },
        image: {
            type: String,
            required: true
        },
        name: {
            type: String,
            trim: true
        },
        category: {
            type: String,
            trim: true
        },
        subcategory: {
            type: String,
            trim: true
        },
        tagline: {
            type: String,
            trim: true
        },
        quantity: {
            type: Number,
            default: 0
        },
        price: {
            type: Number,
        },
    },
    {
        timestamps: true
    }
);

const Product = mongoose.model("Product", productSchema);

export default Product;
