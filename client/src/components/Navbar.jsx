import React, { useContext } from "react";
import { assets } from "../assets/assets";
import { useNavigate } from "react-router-dom";
import { AppContent } from "../context/AppContext";
import { toast } from "react-toastify";
import axios from "axios";
const Navbar = () => {
  const navigate = useNavigate();
  const { userData, backendUrl, setUserData, setIsLoggedin } = useContext(AppContent);

  const sendVerificationOtp= async()=>{
    try {
      axios.defaults.withCredentials=true
      const {data} = await axios.post(backendUrl + '/api/auth/send-verify-otp')
      if(data.success){
        navigate('/email-verify')
        toast.success(data.message)
      }else{
        toast.error(
        error.response?.data?.message || error.message || "Something went wrong"
      );
      }
    } catch (error) {
      toast.error(
        error.response?.data?.message || error.message || "Something went wrong"
      );
    }
  }

  const logout = async () => {
    try {
      axios.defaults.withCredentials = true;
      const { data } = await axios.post(backendUrl + "/api/auth/logout");
      data.success && setIsLoggedin(false);
      data.success && setUserData(false);
      navigate("/");
    } catch (error) {
      toast.error(
        error.response?.data?.message || error.message || "Something went wrong"
      );
    }
  };
  return (
    <div className="w-full flex justify-between items-center p-4 sm:p-6 sm:px-24 absolute top-0">
      <img src={assets.logo} alt="" className="w-28 sm:w-32" />
      {userData ? (
        <div className="relative group">
          <div className="w-8 h-8 flex items-center justify-center rounded-full bg-black text-white text-sm cursor-pointer">
            {userData.name[0].toUpperCase()}
          </div>
          <div className="absolute hidden group-hover:block top-full right-0 bg-white text-black rounded shadow-lg py-2 w-32 z-10">
            <ul className="list-none m-0 p-2 bg-gray-100 text-sm">
              {!userData.isAccountVerified && (
                <li onClick={sendVerificationOtp} className="px-2 py-1 hover:bg-gray-200 cursor-pointer">
                  Verify Email
                </li>
              )}

              <li onClick={logout}  className="px-2 py-1 hover:bg-gray-200 cursor-pointer">
                Logout
              </li>
            </ul>
          </div>
        </div>
      ) : (
        <button
          onClick={() => navigate("/login")}
          className="flex items-center gap-2 border border-gray-500 rounded-full px-6 py-2 text-gray-800 hover:bg-gray-100 transition-all cursor-pointer"
        >
          Login <img src={assets.arrow_icon} alt="" />
        </button>
      )}
    </div>
  );
};

export default Navbar;
