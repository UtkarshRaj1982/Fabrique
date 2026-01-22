const mongoose = require('mongoose');
const dotenv = require('dotenv');
const Product = require('./models/Product');
const User = require('./models/User');
const Cart = require('./models/Cart');
const products = require('./data/products');

dotenv.config({ path: './.env' });

console.log("MONGO_URI:", process.env.MONGO_URI);

mongoose.connect(process.env.MONGO_URI);

//Function to seed the data

const seedData = async () => {
    try {
        //Clear existing data
        await Product.deleteMany();
        await User.deleteMany();
        await Cart.deleteMany();

        //Create a default admin User

        const createdUser =await User.create({
            name: 'Admin User',
            email: 'admin@example.com',
            password:'123456',
            role: 'admin',
        })

        //Assign default user id to each product
        const userID = createdUser._id;

        const sampleProducts = products.map(product => {
            return {...product,user:userID};
          });

        //Insert sample products into the database
        await Product.insertMany(sampleProducts);

        console.log('Products seeded successfully');
        process.exit();
    }catch (error) {
        console.error('Error seeding data:', error);
        process.exit(1);
    }
}

seedData();