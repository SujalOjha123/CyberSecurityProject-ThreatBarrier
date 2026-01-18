import { initializeApp } from "firebase/app";
import {
  getAuth,
  signInWithEmailAndPassword,
  createUserWithEmailAndPassword,
  sendEmailVerification,
  onAuthStateChanged,
  signOut
} from "firebase/auth/web-extension";

const firebaseConfig = {
  apiKey: "AIzaSyAR5T9NkRvSaf70GZf4iiOASt_mfgvp7bc",
  authDomain: "userloginsystem-7dc80.firebaseapp.com",
  projectId: "userloginsystem-7dc80",
  storageBucket: "userloginsystem-7dc80.firebasestorage.app",
  messagingSenderId: "338549874052",
  appId: "1:338549874052:web:c58e670440fee73c3e91d1"
};

const app = initializeApp(firebaseConfig);
export const auth = getAuth(app);

export {
  signInWithEmailAndPassword,
  createUserWithEmailAndPassword,
  sendEmailVerification,
  onAuthStateChanged,
  signOut
};
