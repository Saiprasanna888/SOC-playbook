import { Github, Linkedin } from "lucide-react";

export const MadeWithDyad = () => {
  return (
    <div className="p-4 text-center flex flex-col sm:flex-row items-center justify-center space-y-2 sm:space-y-0 sm:space-x-4">
      <span className="text-sm text-gray-500 dark:text-gray-400">
        Built by Saiprasanna Muppalla
      </span>
      <div className="flex space-x-3">
        <a
          href="https://github.com/Saiprasanna888"
          target="_blank"
          rel="noopener noreferrer"
          className="text-gray-500 hover:text-primary dark:hover:text-primary transition-colors"
          aria-label="GitHub Profile"
        >
          <Github className="w-4 h-4" />
        </a>
        <a
          href="https://www.linkedin.com/in/muppallasaiprasanna/"
          target="_blank"
          rel="noopener noreferrer"
          className="text-gray-500 hover:text-primary dark:hover:text-primary transition-colors"
          aria-label="LinkedIn Profile"
        >
          <Linkedin className="w-4 h-4" />
        </a>
      </div>
    </div>
  );
};