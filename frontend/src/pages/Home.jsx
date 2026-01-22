import { useEffect, useState } from "react";
import { motion } from "framer-motion";
import Hero from "../components/Layout/Hero";
import FeaturedCollection from "../components/Products/FeaturedCollection";
import FeaturedSection from "../components/Products/FeaturedSection";
import GenderCollectionSection from "../components/Products/GenderCollectionSection";
import NewArrivals from "../components/Products/NewArrivals";
import ProductDetails from "../components/Products/ProductDetails";
import ProductGrid from "../components/Products/ProductGrid";
import { useDispatch, useSelector } from "react-redux";
import { fetchProductsByFilter } from "../../redux/slice/productsSlice";
import axios from "axios";
import { Link } from "react-router-dom";

const fadeIn = {
  hidden: { opacity: 0, y: 30 },
  visible: { opacity: 1, y: 0, transition: { duration: 0.6 } },
};

const Home = () => {
  const dispatch = useDispatch();
  const { products, loading, error } = useSelector((state) => state.products);
  const [bestSellerProduct, setBestSellerProduct] = useState(null);

  useEffect(() => {
    dispatch(
      fetchProductsByFilter({
        gender: "Women",
        category: "Bottom Wear",
        limit: 8, // fixed typo from limlt
      })
    );

    const fetchBestSeller = async () => {
      try {
        const response = await axios.get(
          `${import.meta.env.VITE_BACKEND_URL}/api/products/best-seller`
        );
        setBestSellerProduct(response.data);
      } catch (error) {
        console.error(error);
      }
    };

    fetchBestSeller();
  }, [dispatch]);

  return (
    <div className="space-y-20">
      <Hero />

      <motion.div variants={fadeIn} initial="hidden" whileInView="visible" viewport={{ once: true }}>
        <GenderCollectionSection />
      </motion.div>

      <motion.div variants={fadeIn} initial="hidden" whileInView="visible" viewport={{ once: true }}>
        <NewArrivals />
      </motion.div>

      {/* Best Seller Section */}
      <motion.section
        variants={fadeIn}
        initial="hidden"
        whileInView="visible"
        viewport={{ once: true }}
        className="container mx-auto px-4"
      >
        <h2 className="text-3xl font-bold text-center mb-8">Best Seller</h2>
        {bestSellerProduct ? (
          <div className="bg-white shadow-md rounded-lg p-4 sm:p-8">
            <ProductDetails productId={bestSellerProduct._id} />
          </div>
        ) : (
          <p className="text-center text-gray-500">Loading best seller product...</p>
        )}
      </motion.section>

      {/* Top Wear for Women Grid */}
      <motion.section
        variants={fadeIn}
        initial="hidden"
        whileInView="visible"
        viewport={{ once: true }}
        className="container mx-auto px-4"
      >
        <h2 className="text-3xl font-bold text-center mb-8">Top Wear for Women</h2>
        <ProductGrid products={products} loading={loading} error={error} />
        <div className="text-center mt-6">
          <Link
            to="/collections/all?gender=Women&category=Top%20Wear"
            className="inline-block mt-4 px-6 py-3 bg-black text-white rounded hover:bg-gray-800 transition"
          >
            View More
          </Link>
        </div>
      </motion.section>

      <FeaturedCollection />
      <FeaturedSection />
    </div>
  );
};

export default Home;
