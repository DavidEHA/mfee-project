import { getCommentsByPostId } from '../models/comment';

// Get comments by post id
const getCommentsByPostIdHandler = async (req, res) => {
  try {
    const comments = await getCommentsByPostId(req.params.id);
    res.status(200).json(comments);
  } catch (error) {
    res.status(500).json({ message: error.message });
  }
};

export default {
  getPostComments: getCommentsByPostIdHandler
};
