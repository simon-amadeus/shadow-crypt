# Customer Feedback

Add your feedback here. Keep it simple - just write what you think.

---

## New Feedback

*No pending feedback - ready for next input*
- lately we added an abstract configuration system for configuration and algorithm usage. for the sake of refactoring you just used a hardcoded xchacha20 selection but argon2params should be injectable, as well as algorithms. this is required for testing and also for future extensibility. before doing anything else, please scan the entire shared module in order to get an overview of what we have and what we need in order to serve the current requirements of being a future proof file encryption suite.