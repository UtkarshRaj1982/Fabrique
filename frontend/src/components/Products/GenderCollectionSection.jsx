import React from "react";
import mensCollectionimage from "../../assets/mens-collection.webp";
import womensCollectionimage from "../../assets/womens-collection.webp";
import { Link } from "react-router-dom";

const GenderCollectionSection = () => {
  return (
    <section className="py-16 px-4 lg:px-0">
      <div className="container mx-auto grid grid-cols-1 md:grid-cols-2 gap-6">
        {/* Women's Collection */}
        <div className="relative group overflow-hidden rounded-2xl shadow-md">
          <img
            src={womensCollectionimage}
            alt="Women's collection"
            className="w-full h-[500px] md:h-[700px] object-cover transform group-hover:scale-105 transition duration-500"
          />
          <div className="absolute bottom-0 left-0 w-full bg-white/70 backdrop-blur-md p-6 md:p-8">
            <h2 className="text-2xl md:text-3xl font-bold text-gray-900 mb-2">
              Women's Collection
            </h2>
            <Link
              to="/collections/all?gender=Women"
              className="text-sm font-medium text-gray-800 underline hover:text-black transition"
            >
              Shop Now →
            </Link>
          </div>
        </div>

        {/* Men's Collection */}
        <div className="relative group overflow-hidden rounded-2xl shadow-md">
          <img
            src={mensCollectionimage}
            alt="Men's collection"
            className="w-full h-[500px] md:h-[700px] object-cover transform group-hover:scale-105 transition duration-500"
          />
          <div className="absolute bottom-0 left-0 w-full bg-white/70 backdrop-blur-md p-6 md:p-8">
            <h2 className="text-2xl md:text-3xl font-bold text-gray-900 mb-2">
              Men's Collection
            </h2>
            <Link
              to="/collections/all?gender=Men"
              className="text-sm font-medium text-gray-800 underline hover:text-black transition"
            >
              Shop Now →
            </Link>
          </div>
        </div>
      </div>
    </section>
  );
};

export default GenderCollectionSection;
