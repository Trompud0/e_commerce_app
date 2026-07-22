import { useState, useEffect } from 'react';
import { Link } from 'react-router-dom';
import axios from 'axios';
import './Home.css'; 

function Home() {
  const [products, setProducts] = useState([]);
  const [error, setError] = useState('');
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    const fetchProducts = async () => {
      try {
        setLoading(true);
        
        const response = await axios.get('http://localhost:3000/products');
        setProducts(response.data);
        
        setLoading(false);
      } catch (err) {
        setError('Failed to fetch products from the server.');
        setLoading(false);
      }
    };

    fetchProducts();
  }, []);

  if (loading) return <div className="loading">Loading our awesome catalog...</div>;
  if (error) return <div className="error-message">{error}</div>;

  return (
    <div className="catalog-container">
      <h2>Our Storefront Inventory</h2>
      
      <div className="product-grid">
        {products.map((product) => (
          <div key={product.id} className="product-card">
            {product.image_url && (
                <img
                  src={product.image_url}
                  alt={product.product_name}
                  className="product-image"
                />
            )}
            
            <h3>{product.product_name}</h3>
            <p className="product-description">{product.description}</p>
            <p className="product-price">${Number(product.price).toFixed(2)}</p>
            
            {/* Link to click into a single detailed page */}
            <Link to={`/product/${product.id}`} className="view-details-btn">
              View Details
            </Link>
          </div>
        ))}
      </div>
    </div>
  );
}

export default Home;
