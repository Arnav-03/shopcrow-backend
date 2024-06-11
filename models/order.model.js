import mongoose, { Schema } from "mongoose";

const OrderSchema = new Schema(
    {
        paymentId: { type: String, required: true },
        userId: { type: String, required: true },
        items: { type: Array, required: true },
        amount: { type: Number, required: true },
        address: { type: Object, required: true },
        status: { type: String, default: "processing" },
        date: { type: Date, default: Date.now() },
        payment: { type: Boolean, default: false },
    }
);



const Order = mongoose.model("Order", OrderSchema);

export default Order;
