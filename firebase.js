import { initializeApp } from "firebase/app";
import { getAuth } from "firebase/auth";
import { getFirestore } from "firebase/firestore";

const firebaseConfig = {
  apiKey: "AIzaSyCW3qZEfyIVZbZT-9yjqCMei6ZRurlDDXo",
  authDomain: "ziplink32.firebaseapp.com",
  projectId: "ziplink32",
  storageBucket: "ziplink32.firebasestorage.app",
  messagingSenderId: "859454749803",
  appId: "1:859454749803:web:a936c1445818f27f5f052e",
  measurementId: "G-6QXXVVDM17"
};

const app = initializeApp(firebaseConfig);
export const auth = getAuth(app);
export const db = getFirestore(app);