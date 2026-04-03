const mongoose = require('mongoose');
require('dotenv').config();

const connectDB = async () => {
    try {
        await mongoose.connect(process.env.MONGO_URI, {
            useNewUrlParser: true,
            useUnifiedTopology: true
        });
        console.log('MongoDB connected to Atlas!');
    } catch (err) {
        console.error('MongoDB connection failed:', err);
    }
};

module.exports = connectDB;