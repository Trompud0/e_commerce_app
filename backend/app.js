const express = require('express');
const db = require('./db.js');
const app = express();
const port = 3000;
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
require('dotenv').config();

//This Secret Key is mixed with the unique info of the user
//That way, each newly created token is unique 
const JWT_SECRET = process.env.JWT_SECRET;

app.use(express.json());

function authenticateToken(req, res, next) {
  // Get the token from the header
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1]; 

  if (token == null) {
    return res.status(401).json({ message: "No token provided" });
  }

  // Verify the token using the secret key
  jwt.verify(token, JWT_SECRET, (err, user) => {
    if (err) {
      return res.status(403).json({ message: "Invalid or expired token" });
    }

    // Attach the decoded user data to the request object
    req.user = user; 
    
    next(); 
  });
}

app.get('/', (req, res) => {
  res.send('Hello World!')
});

app.listen(port, () => {
  console.log(`Example app listening on port ${port}`)
});

// Registration Route
app.post('/registration', async (req, res, next) => {
  try {
    const { username, email, password, phone, address } = req.body;

    // If any field missing
    if (!username || !email || !password || !phone || !address) {
      return res.status(400).json({ message: "Fill in all fields" });
    }
    
    // If user already exists
    const userCheck = await db.query('SELECT * FROM customers WHERE email = $1', [email]);
    if (userCheck.rows.length > 0) {
      return res.status(400).json({ message: "Email already registered" });
    }

    // Hash the password
    // The number 10 is the "salt rounds" (how much processing power to use)
    const salt = await bcrypt.genSalt(10);
    const hashedPassword = await bcrypt.hash(password, salt);

    // Putting data into db
    // Insert the new customer into the database
    const newUser = await db.query(
      `INSERT INTO customers (username, email, password, phone, address) 
       VALUES ($1, $2, $3, $4, $5) 
       RETURNING id, username, email`, // Don't return the password!
      [username, email, hashedPassword, phone, address]
    );

    res.status(201).json(newUser.rows[0]);

  } catch (error) {
     res.status(500).json({ message: "Error creating customer profile", error: error.message })
  }
});

//Login Route
app.post('/login', async (req, res, next) => {
  try {
    const {username, password} = req.body;   

    //User check
    const userCheck = await db.query('SELECT * FROM customers WHERE username = $1', [username]);
    if (userCheck.rows.length === 0) {
      return res.status(400).json({ message: "Invalid username or password" });
    }

    const user = userCheck.rows[0];

    const isMatch = await bcrypt.compare(password, user.password);

    if (!isMatch) {
      return res.status(400).json({ message: "Invalid username or password" });
    }

    // "Sign" a token containing the user's ID
    const token = jwt.sign(
      { id: user.id, username: user.username }, 
      JWT_SECRET, 
      { expiresIn: '1h' } // Token expires in 1 hour
    );

    res.status(200).json({
      message: "Login successful",
      token: token,
      user: {
        id: user.id,
        username: user.username,
        email: user.email
      }
    });

  } catch (error) {
    res.status(500).json({ message: "Error accessing customer profile", error: error.message })
  }
});


// Reviews Routes

app.get('/products/:productId/reviews', async (req, res, next) => {
   try {
     const queryText = `
       SELECT 
         reviews.*, 
         customers.username 
       FROM reviews 
       INNER JOIN customers ON reviews.customer_id = customers.customer_id 
       WHERE reviews.product_id = $1
       ORDER BY reviews.review_date DESC
     `;

     const result = await db.query(queryText, [req.params.productId]);
     res.json(result.rows);
   } catch (error) {
     res.status(500).json({ message: "Error fetching reviews", error: error.message });
   }
});


//Customers should see their profile information, login , etc

app.get('/profile', authenticateToken, async (req, res, next) => {
  try {
    const queryText = `
      SELECT 
        id, 
        username, 
        email, 
        phone, 
        address 
      FROM customers 
      WHERE id = $1
    `;
    
    const result = await db.query(queryText, [req.user.id]);

    // If no customer is found with that ID
    if (result.rows.length === 0) {
      return res.status(404).json({ message: "Customer profile not found" });
    }

    // Send just the single customer object
    res.json(result.rows[0]);
    
  } catch (error) {
    res.status(500).json({ message: "Error fetching customer profile", error: error.message });
  }
});

app.put('/profile', authenticateToken, async (req, res, next) => {
  try {
    const {username, email, phone, address} = req.body;

    // COALESCE checks for first non null value. 
    // If user only updates phone, then other values won't be forgotten.
    // Will just keep the values that exist and only changes the new value
    const queryText = `
      UPDATE customers 
      SET 
        username = COALESCE($1, username), 
        email    = COALESCE($2, email), 
        phone    = COALESCE($3, phone), 
        address  = COALESCE($4, address) 
      WHERE id = $5 
      RETURNING id, username, email, phone, address
    `;

    // Translates so that SQL and JS work together. SQL knows null, not undefined
    // If username or any entry undefined, will substitute with null
    // This lets COALESCE work properly for partial updates.
    const values = [
      username || null, 
      email || null, 
      phone || null, 
      address || null, 
      req.user.id
    ];

    const result = await db.query(queryText, values);

    if (result.rows.length === 0) {
      return res.status(404).json({ message: "User not found" });
    }

    res.json({ message: "Profile updated!", user: result.rows[0] });

  } catch (error) {
    res.status(500).json({ message: "Error updating profile", error: error.message });
  }
});


//Categories

app.get('/categories/:categoryId', async (req, res, next) => {
  try {
    const queryText = `
      SELECT 
        id, 
        category_name, 
        category_description
      FROM categories 
      WHERE id = $1
    `;

    const result = await db.query(queryText, [req.params.categoryId]);

    if (result.rows.length === 0) {
      return res.status(404).json({ message: "Category not found" });
    }

    res.json(result.rows[0]);

    } catch (error) {
    res.status(500).json({ message: "Error fetching category", error: error.message });
  }
});

app.get('/categories', async (req, res, next) => {
  try {
    const queryText = `
    SELECT 
    
    `;

  } catch (error) {

  }
});

app.get('/categories/:categoryId/products', async (req, res, next) => {

});

//Products

app.get('/products', async (req, res, next) => {

});

app.get('/products/:productId', async (req, res, next) => {

});

//Order

app.get('/orders', async (req, res, next) => {

});

//OrdersItems

app.get('/orders/:orderId', async (req, res, next) => {

});

//Payments

app.get('/payments', async (req, res, next) => {

});