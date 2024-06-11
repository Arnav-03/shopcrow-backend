
const stripeWebhookHandler = async (req: Request, res: Response) => {
    let event;
  
    try {
      const sig = req.headers["stripe-signature"];
      event = STRIPE.webhooks.constructEvent(
        req.body,
        sig as string,
        STRIPE_ENDPOINT_SECRET
      );
    } catch (error: any) {
      console.log(error);
      return res.status(400).send(`Webhook error: ${error.message}`);
    }
  
    if (event.type === "checkout.session.completed") {
      const session = event.data.object as Stripe.Checkout.Session;
      
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
  