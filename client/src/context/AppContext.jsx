import { createContext, useState, useEffect } from "react";
import { toast } from 'react-toastify';
import axios from 'axios';

export const AppContent = createContext();

export const AppContextProvider = (props) => {

    axios.defaults.withCredentials = true

    const backendUrl = import.meta.env.VITE_BACKEND_URL;

    // Debug log to verify the env variable is loaded correctly
    useEffect(() => {
        console.log("✅ Loaded Backend URL:", backendUrl);
        if (!backendUrl) {
            console.warn("❌ VITE_BACKEND_URL is undefined. Make sure .env is set and Vite was restarted.");
        }
    }, [backendUrl]);

    const [isLoggedin, setIsLoggedin] = useState(false);
    const [userData, setUserData] = useState(null); // changed to null (false was incorrect type)

    const getAuthState= async()=>{
        try {
            const {data} = await axios.get(backendUrl + '/api/auth/is-auth')
            if(data.success){
                setIsLoggedin(true)
                getUserData()
            }
        } catch (error) {
            toast.error(error.response?.data?.message || error.message || 'Something went wrong');
        }
    }

    const getUserData = async()=>{
        try {
            const {data} = await axios.get(backendUrl + '/api/user/data')
            data.success ? setUserData(data.userData) : toast.error(data.message)
        } catch (error) {
            toast.error(error.response?.data?.message || error.message || 'Something went wrong');
        }
    }
    useEffect(()=>{
        getAuthState();
    },[])

    const value = {
        backendUrl,
        isLoggedin,
        setIsLoggedin,
        userData,
        setUserData,
        getUserData
    };

    return (
        <AppContent.Provider value={value}>
            {props.children}
        </AppContent.Provider>
    );
};
