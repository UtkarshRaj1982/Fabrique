import React, { useEffect, useState, useRef } from "react";
import { Link } from "react-router-dom";
import { FiChevronLeft, FiChevronRight } from "react-icons/fi";
import axios from "axios";
import { useDispatch, useSelector } from "react-redux";
import { addToCart } from "../../../redux/slice/cartSlice";

// Optional: Toast message component
const Toast = ({ message }) => (
  <div className="fixed top-4 right-4 bg-black text-white py-2 px-4 rounded shadow z-[999] transition-all duration-300">
    {message}
  </div>
);

const NewArrivals = () => {
  const scrollRef = useRef(null);
  const dispatch = useDispatch();
  const { user, guestId } = useSelector((state) => state.auth);

  const [isDragging, setIsDragging] = useState(false);
  const [startX, setStartX] = useState(0);
  const [scrollLeft, setScrollLeft] = useState(0);
  const [canScrollLeft, setCanScrollLeft] = useState(false);
  const [canScrollRight, setCanScrollRight] = useState(true);
  const [isAutoScroll, setIsAutoScroll] = useState(true);
  const [newArrivals, setNewArrivals] = useState([]);
  const [showToast, setShowToast] = useState(false);

  useEffect(() => {
    const fetchNewArrivals = async () => {
      try {
        const response = await axios.get(
          `${import.meta.env.VITE_BACKEND_URL}/api/products/new-arrivals`
        );
        setNewArrivals(response.data);
      } catch (error) {
        console.error(error);
      }
    };
    fetchNewArrivals();
  }, []);

  useEffect(() => {
    if (!scrollRef.current || !isAutoScroll) return;
    const interval = setInterval(() => {
      scroll("right");
    }, 3000);
    return () => clearInterval(interval);
  }, [newArrivals, isAutoScroll]);

  const handleMouseDown = (e) => {
    setIsDragging(true);
    setStartX(e.pageX - scrollRef.current.offsetLeft);
    setScrollLeft(scrollRef.current.scrollLeft);
  };

  const handleMouseMove = (e) => {
    if (!isDragging) return;
    const x = e.pageX - scrollRef.current.offsetLeft;
    const walk = x - startX;
    scrollRef.current.scrollLeft = scrollLeft - walk;
  };

  const handleMouseUpOrLeave = () => {
    setIsDragging(false);
  };

  const scroll = (direction) => {
    const scrollAmount = direction === "left" ? -300 : 300;
    scrollRef.current.scrollBy({ left: scrollAmount, behavior: "smooth" });
  };

  const updateScrollButton = () => {
    const container = scrollRef.current;
    if (container) {
      const leftScroll = container.scrollLeft;
      const rightScrollable =
        container.scrollWidth > leftScroll + container.clientWidth;
      setCanScrollLeft(leftScroll > 0);
      setCanScrollRight(rightScrollable);
    }
  };

  useEffect(() => {
    const container = scrollRef.current;
    if (container) {
      container.addEventListener("scroll", updateScrollButton);
      updateScrollButton();
      return () => container.removeEventListener("scroll", updateScrollButton);
    }
  }, [newArrivals]);

  const handleAddToCart = (product) => {
    const payload = {
      productId: product._id,
      quantity: 1,
      userId: user?._id || null,
      guestId: guestId || null,
      size: product.sizes?.[0] || "M",
      color: product.colors?.[0] || "Black",
    };
    dispatch(addToCart(payload));
    setShowToast(true);
    setTimeout(() => setShowToast(false), 2000); // Hide toast after 2 seconds
  };

  return (
    <section className="py-16 px-4 lg:px-2">
      {showToast && <Toast message="Product added to cart!" />}
      <div className="container mx-auto text-center mb-10 relative">
        <h2 className="text-3xl font-bold mb-4">Explore New Arrivals</h2>
        <p className="text-lg text-gray-600 mb-8">
          Discover the latest styles straight off the runway, freshly added to
          keep your wardrobe on the cutting edge of fashion.
        </p>

        {/* Scroll buttons */}
        <div className="absolute right-0 bottom-[-30px] flex space-x-2 z-10">
          <button
            onClick={() => scroll("left")}
            disabled={!canScrollLeft}
            className={`p-2 rounded border ${
              canScrollLeft
                ? "bg-white text-black"
                : "bg-gray-200 text-gray-400 cursor-not-allowed"
            }`}
          >
            <FiChevronLeft className="text-2xl" />
          </button>
          <button
            onClick={() => scroll("right")}
            disabled={!canScrollRight}
            className={`p-2 rounded border ${
              canScrollRight
                ? "bg-white text-black"
                : "bg-gray-200 text-gray-400 cursor-not-allowed"
            }`}
          >
            <FiChevronRight className="text-2xl" />
          </button>
        </div>
      </div>

       {/*Scrollable Content*/}
      <div
        ref={scrollRef}
        className={`container mx-auto overflow-x-auto flex space-x-6 snap-x snap-mandatory scroll-smooth relative ${
          isDragging ? "cursor-grabbing" : "cursor-grab"
        }`}
        onMouseDown={handleMouseDown}
        onMouseMove={handleMouseMove}
        onMouseUp={handleMouseUpOrLeave}
        onMouseEnter={() => setIsAutoScroll(false)}
        onMouseLeave={() => {
          handleMouseUpOrLeave();
          setIsAutoScroll(true);
        }}
      >
        {newArrivals.map((product) => (
          <div
            key={product._id}
            className="snap-start min-w-[90%] sm:min-w-[50%] lg:min-w-[30%] relative"
          >
            <img
              src={product.images[0]?.url}
              alt={product.images[0]?.altText || product.name}
              className="w-full h-[500px] object-cover rounded-lg"
              draggable="false"
            />
            <div className="absolute bottom-0 left-0 right-0 bg-opacity-50 backdrop-blur-md text-white p-4 rounded-b-lg">
              <Link to={`/product/${product._id}`} className="block">
                <h4 className="font-medium">{product.name}</h4>
                <p className="mt-1">${product.price}</p>
              </Link>
              <button
                onClick={() => handleAddToCart(product)}
                className="mt-2 bg-white text-black px-4 py-2 rounded hover:bg-gray-200 text-sm"
              >
                Add to Cart
              </button>
            </div>
          </div>
        ))}
      </div>
    </section>
  );
};

export default NewArrivals;
