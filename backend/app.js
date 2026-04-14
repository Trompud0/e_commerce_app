const express = require('express');
const db = require('./db.js');
const app = express();
const port = 3000;
const bcrypt = require('bcrypt');

app.use(express.json());

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
    
  } catch (error) {

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


//Customers

app.get('/customers/:customerId', async (req, res, next) => {
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
    
    const result = await db.query(queryText, [req.params.customerId]);

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