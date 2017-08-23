
#include <steemit/protocol/sign_state.hpp>

namespace steemit {
    namespace protocol {

        bool sign_state::signed_by(const public_key_type &k) {
            auto itr = provided_signatures.find(k);
            if (itr == provided_signatures.end()) {
                auto pk = available_keys.find(k);
                if (pk != available_keys.end()) {
                    std::cerr << "12------------- pk != available_keys.end( )"  << "\n";
                    return provided_signatures[k] = true;
                }
                std::cerr << "15------------- signed_by false" << "\n";
                return false;
            }
            std::cerr << "18------------- signed_by true" << "\n";;
            return itr->second = true;
        }

        bool sign_state::check_authority(string id) {
            std::cerr << "23------------- signed_by " << id << "\n";;
            if (approved_by.find(id) != approved_by.end()) {
                std::cerr << "25------------- signed_by  true" << "\n";;
                return true;
            }
            return check_authority(get_active(id));
        }

        bool sign_state::check_authority(const authority &auth, uint32_t depth) {
            uint32_t total_weight = 0;
            for (const auto &k : auth.key_auths) {
                if (signed_by(k.first)) {
                    total_weight += k.second;
                    if (total_weight >= auth.weight_threshold) {
                        std::cerr << "37------------- signed_by true" << std::to_string(total_weight) << "\n";
                        return true;
                    }
                }
            }

            for (const auto &a : auth.account_auths) {
                if (approved_by.find(a.first) == approved_by.end()) {
                    if (depth == max_recursion) {
                        std::cerr << "46------------- signed_by true" << std::to_string(total_weight) << "\n";
                        continue;
                    }
                    if (check_authority(get_active(a.first), depth + 1)) {
                        approved_by.insert(a.first);
                        total_weight += a.second;
                        std::cerr << "52------------- signed_by true" << std::to_string(total_weight) << "\n";
                        if (total_weight >= auth.weight_threshold) {
                            std::cerr << "54------------- signed_by true" << std::to_string(total_weight) << "\n";;
                            return true;
                        }
                    }
                } else {
                    total_weight += a.second;
                    std::cerr << "60------------- signed_by true" << std::to_string(total_weight) << "\n";
                    if (total_weight >= auth.weight_threshold) {
                        std::cerr << "62------------- signed_by true" << std::to_string(total_weight) << "\n";
                        return true;
                    }
                }
            }
            std::cerr << "67------------- total_weighte" << std::to_string(total_weight) << "\n";
            std::cerr << "68------------- weight_threshold" << std::to_string(auth.weight_threshold) << "\n";;
            return total_weight >= auth.weight_threshold;
        }

        bool sign_state::remove_unused_signatures() {
            vector<public_key_type> remove_sigs;
            for (const auto &sig : provided_signatures) {
                if (!sig.second) {
                    remove_sigs.push_back(sig.first);
                }
            }

            for (auto &sig : remove_sigs) {
                provided_signatures.erase(sig);
            }

            return remove_sigs.size() != 0;
        }

        sign_state::sign_state(
                const flat_set<public_key_type> &sigs,
                const authority_getter &a,
                const flat_set<public_key_type> &keys
        ) : get_active(a), available_keys(keys) {
            for (const auto &key : sigs) {
                provided_signatures[key] = false;
            }
            approved_by.insert("temp");
        }

    }
} // steemit::protocol
