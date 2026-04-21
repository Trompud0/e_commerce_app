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


//Authentication middleware
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

//
//Products
//

app.get('/products', async (req, res, next) => {
  try {
    const queryText = `
      SELECT *
      FROM products
    `;
    
    const result = await db.query(queryText);
    
    res.json(result.rows[0]);

  } catch (error) {
    res.status(500).json({ message: "Error fetching products", error: error.message });
  }
});

app.get('/products/:productId', async (req, res, next) => {
  try {
    const queryText = `
      SELECT *
      FROM products
      WHERE id = $1
    `;

    const result = await db.query(queryText, [req.params.productId]);

    if (result.rows.length === 0) {
      return res.status(404).json({ message: "Product not found" });
    }

    res.json(result.rows[0]);

  } catch (error) {
   res.status(500).json({ message: "Error fetching product", error: error.message }); 
  }
});

//
//Order Section
//


// Lets you see Orders
app.get('/orders', authenticateToken, async (req, res, next) => {
  try {
    const queryText = `
      SELECT 
        id,
        order_date,
        order_status
      FROM orders
      WHERE customer_id = $1 
      ORDER BY order_date DESC
    `;

    const result = await db.query(queryText, [req.user.id]);
    
    if (result.rows.length === 0) {
      return res.status(200).json({message:"You haven't placed any orders yet."});
    }

    res.json(result.rows);
  } catch (error) {
    res.status(500).json({ message: "Error fetching order history", error: error.message });
  }
});


//Lets you see what is in an Order
app.get('/orders/:orderId', authenticateToken, async (req, res, next) => {
  try {
    const queryText = `
      SELECT 
        orderitems.quantity, 
        orderitems.price_at_purchase, 
        products.product_name 
      FROM orderitems
      JOIN products ON orderitems.product_id = products.id
      JOIN orders ON orderitems.order_id = orders.id
      WHERE orderitems.order_id = $1 AND orders.customer_id = $2
    `;
    
    const result = await db.query(queryText, [req.params.orderId, req.user.id]);
    
    if (result.rows.length === 0) {
      return res.status(404).json({ message: "Order not found or access denied" });
    }

    res.json(result.rows);
  } catch (error) {
    res.status(500).json({ message: "Error fetching order details", error: error.message });
  }
});

//Can create an order
app.post('/orders', authenticateToken, async (req, res, next) => {
  const { items } = req.body; // Expecting an array of { product_id, quantity, price }
  const customerId = req.user.id; // From the JWT
  
  try {
    // 1. START the Transaction
    // This tells the db to put this in temporary workspace until transaction completed 
    await db.query('BEGIN');

    // 2. Create the Order "header"
    // The RETURNING id part important. Lets you know the id of the new row that was created.
    // This will then be sent to step 3.
    const orderResult = await db.query(
      'INSERT INTO orders (customer_id, order_date, order_status) VALUES ($1, NOW(), $2) RETURNING id',
      [customerId, 'pending']
    );
    const orderId = orderResult.rows[0].id;

    // 3. Loop through items and insert each into order_items
    for (const item of items) {
      await db.query(
        'INSERT INTO orderitems (order_id, product_id, quantity, price_at_purchase) VALUES ($1, $2, $3, $4)',
        [orderId, item.product_id, item.quantity, item.price_at_purchase]
      );

      // Updates the stock quantity 
      await db.query(
        'UPDATE products SET stock_quantity = stock_quantity - $1 WHERE id = $2',
        [item.quantity, item.product_id]
      );
    }

    // 4. COMMIT the Transaction (Save everything for real)
    await db.query('COMMIT');

    res.status(201).json({ message: "Order placed successfully", orderId });

  } catch (error) {
    // 5. ROLLBACK if anything goes wrong (Deletes the partial order)
    await db.query('ROLLBACK');
    res.status(500).json({ message: "Order failed", error: error.message });
  }
});


// Cart

app.post('/cart', authenticateToken, async (req, res, next) => {
  try {
    const { product_id, quantity } = req.body;
    const customer_id = req.user.id;

    // 1. Check if the product exists and has enough stock
    const products = await db.query('SELECT stock_quantity FROM products WHERE id = $1', [product_id]);
    
    if (products) {

    }

  } catch (error) {
    res.status(500).json({ message: "Error adding to cart", error: error.message });
  }
});

app.get('/cart', authenticateToken, async (req, res, next) => {
  try {
    const queryText = `
      SELECT 
        c.id as cart_item_id, 
        p.product_name, 
        p.price, 
        c.quantity, 
        (p.price * c.quantity) AS subtotal
      FROM cart_items c
      JOIN products p ON c.product_id = p.id
      WHERE c.customer_id = $1
    `;
    const result = await db.query(queryText, [req.user.id]);
    res.json(result.rows);

  } catch (error) {
    res.status(500).json({ message: "Error fetching cart", error: error.message });
  }
});

app.delete('/cart/:itemId', authenticateToken, async (req, res, next) => {
  try {
    await db.query('DELETE FROM cart_items WHERE id = $1 AND customer_id = $2', [req.params.itemId, req.user.id]);
    res.json({ message: "Item removed from cart" });
  } catch (error) {
    res.status(500).json({ message: "Error deleting item from the cart", error: error.message });
  }
});

//Checkout route (involves Payments table)

app.post('/checkout', async (req, res, next) => {

});