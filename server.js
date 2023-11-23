import express from 'express';
import dotenv from 'dotenv';
import mongoose from 'mongoose';
import bodyParser from 'body-parser';
import bcrypt from 'bcrypt';
import User from './user.js';
import jwt from 'jsonwebtoken';
dotenv.config();
import OpenAI from 'openai';
const app = express();
const port = process.env.PORT;

// Connect to MongoDB
mongoose
	.connect(process.env.MONGO_URI, { useNewUrlParser: true, useUnifiedTopology: true })
	.then(() => console.log('MongoDB Connected'))
	.catch((err) => console.error(err));

const openai = new OpenAI({
	apiKey: process.env.OPENAI_API_KEY,
});
app.use(express.json());

app.post('/chat', async (req, res) => {
	try {
		const userMessage = req.body.message;
		const chatCompletion = await openai.chat.completions.create({
			model: 'gpt-3.5-turbo',
			messages: [{ role: 'user', content: userMessage }],
		});
		const botReply = chatCompletion.choices[0].message.content;
		res.json({ reply: botReply });
	} catch (error) {
		console.log(error);
		res.status(500).json({ error: 'Internal server error' });
	}
});
app.post('/register', async (req, res) => {
	const { username, email, password } = req.body;

	// Validate the data

	// Hash the password
	const hashedPassword = await bcrypt.hash(password, 10);

	// Save the user to MongoDB
	const newUser = new User({ username, email, password: hashedPassword });
	try {
		await newUser.save();
		res.status(201).json({ message: 'User registered successfully' });
	} catch (error) {
		console.error(error);
		res.status(500).json({ message: 'Internal server error' });
	}
});
app.post('/login', async (req, res) => {
	const { email, password } = req.body;

	// Validate the data

	try {
		// Check if the user exists in the database
		const user = await User.findOne({ email });

		// Verify the password
		if (!user || !(await bcrypt.compare(password, user.password))) {
			return res.status(401).json({ message: 'Invalid credentials' });
		}

		const secretKey = process.env.JWT_SECRET;
		// Generate a token
		const token = jwt.sign({ userId: user._id, email: user.email }, secretKey, {
			expiresIn: '5m',
		});
		// Send a successful login message with the token
		res.status(200).json({ message: 'Login successful', token });
	} catch (error) {
		console.error(error);
		res.status(500).json({ message: 'Internal server error' });
	}
});
// Handle React routing, return all requests to React app
app.get('/api', (req, res) => {
	// res.sendFile(path.join(__dirname, 'build', 'index.html'));
	res.json('working');
});

app.listen(port, () => {
	console.log(`Server is running on port ${port}`);
});
